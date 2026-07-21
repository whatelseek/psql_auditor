"""Host inventory facts: LLM gather + parsers, CMDB drift, inventory helpers."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class HostFacts:
    hostname: str = ""
    ips: list[str] = field(default_factory=list)
    disk: str = ""
    ram: str = ""
    cpu: str = ""
    os_id: str = ""
    os_version_id: str = ""
    os_pretty_name: str = ""
    binaries: list[str] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)
    collected_at: str = ""
    error: str = ""
    ssh_host: str = ""


@dataclass
class DriftItem:
    field: str
    expected: str
    observed: str
    status: str  # match | mismatch | missing_cmdb | missing_host


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.lower().startswith("exit_code"):
            return line
    return ""


def parse_hostname(stdout: str) -> str:
    # Prefer hostnamectl Static hostname / Pretty, else first non-empty line
    for line in (stdout or "").splitlines():
        if "static hostname" in line.lower() or "static hostname:" in line.lower():
            return line.split(":", 1)[-1].strip()
        if line.lower().startswith("hostname:"):
            return line.split(":", 1)[-1].strip()
    return _first_line(stdout)


def parse_ips(stdout: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
        stdout or "",
    ):
        ip = match.group(0)
        if ip.startswith("127."):
            continue
        if ip not in found:
            found.append(ip)
    return found


def parse_os_release(stdout: str) -> tuple[str, str, str]:
    """Parse ``/etc/os-release`` → ``(id, version_id, pretty_name)``."""
    data: dict[str, str] = {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip().strip('"').strip("'")
        data[key.strip().upper()] = val
    # Windows PowerShell probe may emit OS=Windows_NT
    if "windows" in (stdout or "").lower() and "ID" not in data:
        return "windows", data.get("VERSION_ID", ""), data.get("PRETTY_NAME", "Windows")
    return (
        data.get("ID", "").lower(),
        data.get("VERSION_ID", ""),
        data.get("PRETTY_NAME", ""),
    )


def parse_binaries_present(stdout: str) -> list[str]:
    """Parse ``command -v`` / which probe lines: ``name=/path`` or ``name=``."""
    skip = {"exit_code", "stdout", "stderr"}
    found: list[str] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if "=" not in line or line.lower().startswith("exit_code="):
            continue
        name, _, path = line.partition("=")
        name = name.strip().lower()
        path = path.strip()
        if name in skip:
            continue
        if name and path and path.lower() not in {"", "missing", "not found"}:
            if name not in found:
                found.append(name)
    return found


def parse_listening_ports(stdout: str) -> list[int]:
    """Extract listening TCP ports from ``ss`` / ``netstat`` style output."""
    ports: list[int] = []
    for match in re.finditer(r":(\d{1,5})\b", stdout or ""):
        try:
            port = int(match.group(1))
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def parse_host_facts_json(
    payload: dict[str, Any] | None,
    *,
    ssh_host: str = "",
    raw: dict[str, str] | None = None,
) -> HostFacts:
    """Build ``HostFacts`` from an LLM fill JSON object."""
    data = payload if isinstance(payload, dict) else {}
    ips_raw = data.get("ips") or []
    if isinstance(ips_raw, str):
        ips = parse_ips(ips_raw)
    else:
        ips = parse_ips(" ".join(str(p) for p in ips_raw if str(p).strip()))

    binaries_raw = data.get("binaries") or []
    if isinstance(binaries_raw, str):
        binaries = [
            p.strip().lower()
            for p in re.split(r"[\s,;]+", binaries_raw)
            if p.strip()
        ]
    else:
        binaries = [str(b).strip().lower() for b in binaries_raw if str(b).strip()]

    ports: list[int] = []
    ports_raw = data.get("listening_ports") or []
    if isinstance(ports_raw, (str, int)):
        ports_raw = [ports_raw]
    for p in ports_raw:
        try:
            port = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)

    os_id = str(data.get("os_id") or "").strip().lower()
    return HostFacts(
        hostname=str(data.get("hostname") or "").strip(),
        ips=ips,
        disk=str(data.get("disk") or "").strip(),
        ram=str(data.get("ram") or "").strip(),
        cpu=str(data.get("cpu") or "").strip(),
        os_id=os_id,
        os_version_id=str(data.get("os_version_id") or "").strip(),
        os_pretty_name=str(data.get("os_pretty_name") or "").strip(),
        binaries=binaries,
        listening_ports=ports,
        raw=dict(raw or {}),
        collected_at=datetime.now(timezone.utc).isoformat(),
        error=str(data.get("error") or "").strip(),
        ssh_host=ssh_host or str(data.get("ssh_host") or "").strip(),
    )


def merge_facts_from_raw(facts: HostFacts, raw: dict[str, str] | None = None) -> HostFacts:
    """Fill empty HostFacts fields using deterministic parsers on tool stdout.

    Used when the LLM fill JSON is incomplete. ``raw`` keys may be semantic
    (``hostname``, ``os``, …) or opaque (``tool_1``, …); for opaque blobs the
    full concatenated text is also scanned.
    """
    blob_map = dict(raw or facts.raw or {})
    facts.raw = blob_map
    combined = "\n".join(str(v) for v in blob_map.values() if v)

    if not facts.hostname:
        facts.hostname = parse_hostname(
            blob_map.get("hostname", "") or combined
        )
    if not facts.ips:
        facts.ips = parse_ips(blob_map.get("ips", "") or combined)

    if not facts.os_id or not facts.os_pretty_name:
        os_src = blob_map.get("os", "") or combined
        os_id, os_ver, os_pretty = parse_os_release(os_src)
        if not os_id and "linux" in os_src.lower():
            os_id = "linux"
        if not facts.os_id and os_id:
            facts.os_id = os_id
        if not facts.os_version_id and os_ver:
            facts.os_version_id = os_ver
        if not facts.os_pretty_name and os_pretty:
            facts.os_pretty_name = os_pretty

    if not facts.binaries:
        facts.binaries = parse_binaries_present(
            blob_map.get("binaries", "") or combined
        )
    if not facts.listening_ports:
        facts.listening_ports = parse_listening_ports(
            blob_map.get("ports", "") or combined
        )

    if not facts.disk and blob_map.get("disk"):
        facts.disk = blob_map["disk"].strip()
    elif not facts.disk and "Filesystem" in combined:
        # Keep a short df-like slice when present in tool dumps
        disk_lines = [
            ln
            for ln in combined.splitlines()
            if ln.strip().startswith("Filesystem") or re.match(r"^/\S*", ln.strip())
        ]
        if disk_lines:
            facts.disk = "\n".join(disk_lines[:20]).strip()

    if not facts.ram:
        ram_src = blob_map.get("ram", "")
        if ram_src:
            ram_lines = [
                ln
                for ln in ram_src.splitlines()
                if ln.strip() and not ln.lower().startswith("exit_code")
            ]
            facts.ram = " | ".join(ram_lines[:4])
        elif "MemTotal" in combined or "Mem:" in combined:
            ram_lines = [
                ln
                for ln in combined.splitlines()
                if "MemTotal" in ln or "MemAvailable" in ln or ln.strip().startswith("Mem:")
            ]
            facts.ram = " | ".join(ram_lines[:4])

    if not facts.cpu:
        cpu_src = blob_map.get("cpu", "")
        if cpu_src:
            cpu_lines = [
                ln
                for ln in cpu_src.splitlines()
                if ln.strip() and not ln.lower().startswith("exit_code")
            ]
            facts.cpu = " | ".join(cpu_lines[:4])
        elif "Model name" in combined or "nproc" in combined.lower():
            cpu_lines = [
                ln
                for ln in combined.splitlines()
                if "Model name" in ln or "CPU(s)" in ln or re.match(r"^\d+$", ln.strip())
            ]
            facts.cpu = " | ".join(cpu_lines[:4])

    if not facts.error and "ssh error" in combined.lower():
        for line in combined.splitlines():
            if "ssh error" in line.lower():
                facts.error = line.strip()
                break

    return facts


def compare_to_netbox(
    facts: HostFacts,
    netbox_device: dict[str, Any] | None,
) -> list[DriftItem]:
    """Highlight hostname / IP differences vs a NetBox device record."""
    if not netbox_device:
        return [
            DriftItem(
                field="device",
                expected="(none)",
                observed=facts.hostname or "(unknown)",
                status="missing_cmdb",
            )
        ]
    items: list[DriftItem] = []
    nb_name = str(
        netbox_device.get("name")
        or netbox_device.get("display")
        or netbox_device.get("hostname")
        or ""
    ).strip()
    if facts.hostname and nb_name:
        status = "match" if facts.hostname.lower() == nb_name.lower() else "mismatch"
        items.append(
            DriftItem(
                field="hostname",
                expected=nb_name,
                observed=facts.hostname,
                status=status,
            )
        )
    elif facts.hostname and not nb_name:
        items.append(
            DriftItem(
                field="hostname",
                expected="(missing in NetBox)",
                observed=facts.hostname,
                status="missing_cmdb",
            )
        )

    nb_ip = ""
    primary = netbox_device.get("primary_ip4") or netbox_device.get("primary_ip")
    if isinstance(primary, dict):
        nb_ip = str(primary.get("address") or primary.get("display") or "").split("/")[0]
    elif isinstance(primary, str):
        nb_ip = primary.split("/")[0]
    nb_ip = nb_ip.strip()
    if facts.ips and nb_ip:
        status = "match" if nb_ip in facts.ips else "mismatch"
        items.append(
            DriftItem(
                field="ip",
                expected=nb_ip,
                observed=", ".join(facts.ips),
                status=status,
            )
        )
    elif facts.ips and not nb_ip:
        items.append(
            DriftItem(
                field="ip",
                expected="(missing in NetBox)",
                observed=", ".join(facts.ips),
                status="missing_cmdb",
            )
        )
    return items


def facts_to_dict(facts: HostFacts) -> dict[str, Any]:
    return asdict(facts)


def write_host_facts_json(path: Path, facts: HostFacts, drift: list[DriftItem]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "facts": facts_to_dict(facts),
        "drift": [asdict(d) for d in drift],
        "written_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def format_host_facts_markdown(
    facts: HostFacts,
    drift: list[DriftItem] | None = None,
    *,
    language: str = "en",
) -> str:
    ru = language.startswith("ru")
    lines = [
        "## " + ("Факты о хосте" if ru else "Host facts"),
        "",
    ]
    if facts.error:
        lines.append(f"**Error:** {facts.error}")
        lines.append("")
    lines.extend(
        [
            f"- **Hostname:** {facts.hostname or '—'}",
            f"- **SSH target:** {facts.ssh_host or '—'}",
            f"- **OS:** {facts.os_pretty_name or facts.os_id or '—'}"
            + (f" ({facts.os_version_id})" if facts.os_version_id else ""),
            f"- **IPs:** {', '.join(facts.ips) if facts.ips else '—'}",
            f"- **Binaries:** {', '.join(facts.binaries) if facts.binaries else '—'}",
            f"- **Listening ports:** "
            + (
                ", ".join(str(p) for p in facts.listening_ports)
                if facts.listening_ports
                else "—"
            ),
            f"- **CPU:** {facts.cpu or '—'}",
            f"- **RAM:** {facts.ram or '—'}",
            f"- **Disk:**",
            "",
            "```",
            (facts.disk or "—")[:4000],
            "```",
            "",
        ]
    )
    if drift:
        title = "Расхождения с CMDB (NetBox)" if ru else "CMDB drift (NetBox)"
        lines.extend([f"## {title}", "", "| Field | Expected | Observed | Status |", "|---|---|---|---|"])
        for item in drift:
            mark = item.status
            if item.status == "mismatch":
                mark = f"**{item.status}**"
            lines.append(
                f"| {item.field} | {item.expected} | {item.observed} | {mark} |"
            )
        lines.append("")
    return "\n".join(lines)


def upsert_inventory_md(
    inventory_path: Path,
    *,
    client_name: str,
    facts: HostFacts | None = None,
    scope_text: str = "",
    reachable_services: list[dict[str, Any]] | None = None,
) -> Path:
    """Create or refresh INVENTORY.md for a client when CMDB is absent.

    Preserves an existing ``## Credentials`` / ``## Credentials & access``
    section so operator secrets are not wiped on host-facts refresh.
    """
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    creds_block = ""
    if inventory_path.is_file():
        existing = inventory_path.read_text(encoding="utf-8")
        match = re.search(
            r"(##\s+Credentials(?:\s*&\s*access)?\s*\n.*?)(?=\n##\s|\Z)",
            existing,
            re.IGNORECASE | re.DOTALL,
        )
        if match:
            creds_block = match.group(1).rstrip() + "\n\n"

    now = datetime.now(timezone.utc).isoformat()
    lines = [
        f"# Inventory — {client_name}",
        "",
        f"_Updated: {now}_",
        "",
    ]
    if creds_block:
        lines.append(creds_block.rstrip("\n"))
        lines.append("")
    lines.extend(
        [
            "## Scope",
            "",
            (scope_text.strip() or "_No scope document was available._"),
            "",
        ]
    )
    if reachable_services:
        lines.extend(["## Reachable services", "", "| Service | Status | Detail |", "|---|---|---|"])
        for svc in reachable_services:
            lines.append(
                f"| {svc.get('name')} | {svc.get('status')} | {svc.get('detail') or '—'} |"
            )
        lines.append("")
    if facts is not None:
        lines.extend(
            [
                "## Host",
                "",
                f"- Hostname: `{facts.hostname or '—'}`",
                f"- SSH: `{facts.ssh_host or '—'}`",
                f"- OS: `{facts.os_pretty_name or facts.os_id or '—'}`",
                f"- IPs: {', '.join(f'`{ip}`' for ip in facts.ips) or '—'}",
                f"- Binaries: {', '.join(facts.binaries) if facts.binaries else '—'}",
                f"- CPU: {facts.cpu or '—'}",
                f"- RAM: {facts.ram or '—'}",
                "",
                "### Disk",
                "",
                "```",
                (facts.disk or "—")[:4000],
                "```",
                "",
            ]
        )
    inventory_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return inventory_path


def resolve_client_dir(
    inventory_dir: Path,
    client_slug_name: str,
    *,
    display_name: str | None = None,
) -> Path:
    """Resolve ``inventory/<client>/`` with case-insensitive folder match.

    Prefer an existing directory whose name matches the slug ignoring case
    (e.g. ``TestCompany`` for slug ``testcompany``). When several case variants
    exist, prefer ``display_name`` casing, then mixed-case over all-lowercase.
    Otherwise return the path for ``display_name`` (sanitized) or the slug.
    """
    from auditor.evidence_store import client_artifacts_id

    inventory_dir = Path(inventory_dir)
    slug = (client_slug_name or "").strip()
    if not slug and not display_name:
        return inventory_dir / "client"

    preferred_name = (
        client_artifacts_id(display_name) if display_name else (slug or "client")
    )
    if inventory_dir.is_dir():
        lower = (slug or preferred_name).lower()
        matches = [
            child
            for child in inventory_dir.iterdir()
            if child.is_dir() and child.name.lower() == lower
        ]
        if matches:
            for child in matches:
                if child.name == preferred_name:
                    return child
            matches.sort(key=lambda p: (p.name.islower(), len(p.name), p.name))
            return matches[0]

    preferred = inventory_dir / preferred_name
    if preferred.is_dir():
        return preferred
    # Fallback: lowercase slug path (legacy)
    if slug:
        legacy = inventory_dir / slug
        if legacy.is_dir():
            return legacy
    return preferred


def resolve_client_inventory(
    inventory_dir: Path,
    client_slug_name: str,
) -> tuple[Path | None, str, bool]:
    """Locate ``inventory/<client>/INVENTORY.md`` before asking about access.

    Returns:
        ``(path, content_or_message, found)``. Does **not** fall back to the
        example template — that file is documentation only.
    """
    inventory_dir = Path(inventory_dir)
    slug = (client_slug_name or "").strip()
    if not slug:
        return (
            None,
            "No client slug — cannot resolve inventory/<client>/INVENTORY.md.",
            False,
        )
    client_dir = resolve_client_dir(inventory_dir, slug)
    path = client_dir / "INVENTORY.md"
    if path.is_file():
        return path, path.read_text(encoding="utf-8"), True
    client_dir.mkdir(parents=True, exist_ok=True)
    return (
        path,
        (
            f"No inventory file found at `{path}`.\n\n"
            f"Create that file with audit scope **and** a credentials table "
            f"(SSH/PG/NetBox hosts, ports, users), or copy from "
            f"`inventory/INVENTORY.example.md`, then continue."
        ),
        False,
    )


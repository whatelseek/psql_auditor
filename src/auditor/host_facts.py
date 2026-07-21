"""Deterministic host inventory facts via SSH + CMDB drift helpers."""

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


async def collect_host_facts_ssh() -> HostFacts:
    """Run fixed SSH commands and parse hostname / OS / software / capacity."""
    from auditor.tools.ssh import ssh_run
    from auditor.config import get_settings

    settings = get_settings()
    facts = HostFacts(
        collected_at=datetime.now(timezone.utc).isoformat(),
        ssh_host=str(settings.ssh_host or ""),
    )
    commands = {
        "hostname": "hostname -f 2>/dev/null || hostname; hostnamectl 2>/dev/null | head -n 20",
        "ips": "hostname -I 2>/dev/null; ip -4 -o addr show 2>/dev/null | awk '{print $4}'",
        "disk": "df -h 2>/dev/null | head -n 20",
        "ram": "free -m 2>/dev/null; echo '---'; grep -E 'MemTotal|MemAvailable' /proc/meminfo 2>/dev/null",
        "cpu": "nproc 2>/dev/null; lscpu 2>/dev/null | grep -E 'Model name|CPU\\(s\\)|Thread|Core' | head -n 20",
        "os": (
            "if [ -f /etc/os-release ]; then cat /etc/os-release; "
            "elif command -v powershell >/dev/null 2>&1; then "
            "powershell -NoProfile -Command "
            "\"Write-Output ('ID=windows'); Write-Output ('PRETTY_NAME=' + [System.Environment]::OSVersion.VersionString)\"; "
            "elif command -v pwsh >/dev/null 2>&1; then "
            "pwsh -NoProfile -Command "
            "\"Write-Output ('ID=windows'); Write-Output ('PRETTY_NAME=' + [System.Environment]::OSVersion.VersionString)\"; "
            "else uname -a; fi"
        ),
        "binaries": (
            "for c in postgres psql docker nginx apache2 httpd; do "
            "p=$(command -v \"$c\" 2>/dev/null || true); "
            "echo \"$c=${p:-}\"; done"
        ),
        "ports": (
            "ss -lnt 2>/dev/null | head -n 40 || "
            "netstat -lnt 2>/dev/null | head -n 40 || true"
        ),
    }
    try:
        for key, cmd in commands.items():
            result = await ssh_run.ainvoke({"command": cmd})
            text = str(result or "")
            facts.raw[key] = text
            if text.lower().startswith("ssh error"):
                facts.error = text
                return facts
        facts.hostname = parse_hostname(facts.raw.get("hostname", ""))
        facts.ips = parse_ips(facts.raw.get("ips", ""))
        facts.disk = facts.raw.get("disk", "").strip()
        # Compact RAM / CPU one-liners for tables
        ram_lines = [
            ln
            for ln in facts.raw.get("ram", "").splitlines()
            if ln.strip() and not ln.lower().startswith("exit_code")
        ]
        facts.ram = " | ".join(ram_lines[:4])
        cpu_lines = [
            ln
            for ln in facts.raw.get("cpu", "").splitlines()
            if ln.strip() and not ln.lower().startswith("exit_code")
        ]
        facts.cpu = " | ".join(cpu_lines[:4])
        os_id, os_ver, os_pretty = parse_os_release(facts.raw.get("os", ""))
        if not os_id and "linux" in (facts.raw.get("os") or "").lower():
            os_id = "linux"
        facts.os_id = os_id
        facts.os_version_id = os_ver
        facts.os_pretty_name = os_pretty
        facts.binaries = parse_binaries_present(facts.raw.get("binaries", ""))
        facts.listening_ports = parse_listening_ports(facts.raw.get("ports", ""))
    except Exception as exc:  # noqa: BLE001
        facts.error = f"{type(exc).__name__}: {exc}"
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


def read_inventory_scope(inventory_dir: Path, client_slug_name: str = "") -> str:
    """Return client inventory contents, or a missing-file message (no example dump)."""
    _path, text, _found = resolve_client_inventory(inventory_dir, client_slug_name)
    return text


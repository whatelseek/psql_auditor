"""Load Markdown / YAML / JSON client inventories into a raw structure."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from auditor.inventory.client_name import InvalidClientNameError, validate_client_name

_TABLE_ROW = re.compile(r"^\|(.+)\|$")
_SUPPORTED_NAMES = (
    "INVENTORY.md",
    "INVENTORY.yaml",
    "INVENTORY.yml",
    "INVENTORY.json",
    "inventory.md",
    "inventory.yaml",
    "inventory.yml",
    "inventory.json",
)


class InventoryLoadError(ValueError):
    """Raised when inventory cannot be located or parsed."""


def resolve_inventory_file(client_dir: Path) -> Path:
    """Locate a supported inventory file under the client directory."""
    for name in _SUPPORTED_NAMES:
        path = client_dir / name
        if path.is_file():
            return path
    raise InventoryLoadError(
        f"missing inventory file under {client_dir} "
        f"(expected one of: {', '.join(_SUPPORTED_NAMES[:4])})"
    )


def detect_format(path: Path) -> str:
    """Return ``markdown``, ``yaml``, or ``json`` from file suffix."""
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".json":
        return "json"
    raise InventoryLoadError(f"unsupported inventory format: {path.suffix!r}")


def load_raw_inventory(
    inventory_dir: Path | str,
    client_name: str,
) -> tuple[dict[str, Any], Path, str]:
    """Load client inventory into a raw dict plus path/format metadata.

    Args:
        inventory_dir: Root ``inventory/`` directory.
        client_name: Strict client name (Latin/digit/underscore).

    Returns:
        ``(raw_document, source_path, format_name)``.
    """
    try:
        client = validate_client_name(client_name)
    except InvalidClientNameError as exc:
        raise InventoryLoadError(str(exc)) from exc

    root = Path(inventory_dir)
    # Prefer exact casing (Testcompany), then case-insensitive match.
    client_dir = root / client
    if not client_dir.is_dir():
        matches = (
            [
                child
                for child in root.iterdir()
                if child.is_dir() and child.name.lower() == client.lower()
            ]
            if root.is_dir()
            else []
        )
        if matches:
            client_dir = matches[0]
        else:
            raise InventoryLoadError(f"client inventory directory not found: {root / client}")

    path = resolve_inventory_file(client_dir)
    fmt = detect_format(path)
    text = path.read_text(encoding="utf-8")
    if fmt == "json":
        raw = _load_json(text, path)
    elif fmt == "yaml":
        raw = _load_yaml(text, path)
    else:
        raw = _load_markdown(text, client)
    raw.setdefault("client", client)
    return raw, path, fmt


def _load_json(text: str, path: Path) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InventoryLoadError(f"invalid JSON inventory at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise InventoryLoadError(f"JSON inventory root must be an object: {path}")
    return data


def _load_yaml(text: str, path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InventoryLoadError(f"invalid YAML inventory at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise InventoryLoadError(f"YAML inventory root must be a mapping: {path}")
    return data


def _cell(raw: str) -> str:
    return (raw or "").strip().strip("`")


def _norm_header(cell: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (cell or "").lower())


def _split_list(value: str) -> list[str]:
    parts = re.split(r"[,;/|]+", value or "")
    return [p.strip() for p in parts if p.strip()]


def _parse_markdown_table(text: str, *, required_headers: set[str]) -> list[dict[str, str]]:
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        match = _TABLE_ROW.match(line.strip())
        if not match:
            continue
        cells = [_cell(c) for c in match.group(1).split("|")]
        norms = [_norm_header(c) for c in cells]
        if not required_headers.intersection(norms):
            continue
        rows: list[dict[str, str]] = []
        for line2 in lines[i + 1 :]:
            stripped = line2.strip()
            if not stripped.startswith("|"):
                if rows:
                    break
                continue
            if re.match(r"^\|[\s|:-]+\|$", stripped):
                continue
            body = [_cell(c) for c in stripped.strip("|").split("|")]
            if len(body) < len(norms):
                body.extend([""] * (len(norms) - len(body)))
            row = {norms[j]: body[j] for j in range(len(norms))}
            rows.append(row)
        return rows
    return []


def _load_markdown(text: str, client: str) -> dict[str, Any]:
    """Parse Markdown inventory tables into a structured raw document."""
    host_rows = _parse_markdown_table(
        text,
        required_headers={"hostname", "host", "hostid", "ip"},
    )
    # Prefer an in-scope hosts table (hostname/os/services/role), not credentials.
    asset_rows = [
        r
        for r in host_rows
        if any(
            k in r
            for k in (
                "hostname",
                "hostid",
                "os",
                "operatingsystem",
                "services",
                "discoveredservices",
                "role",
                "roles",
            )
        )
        and not (
            "access" in r
            and (
                "passwordtoken" in r or "password" in r or "username" in r or "secretreference" in r
            )
        )
    ]
    if asset_rows:
        preferred = asset_rows
    else:
        # Fall back: credentials-derived hosts when only a credentials table exists.
        preferred = [
            r
            for r in host_rows
            if r.get("access") or r.get("host") or r.get("hosturl") or r.get("hostname")
        ]

    hosts: list[dict[str, Any]] = []
    for idx, row in enumerate(preferred, start=1):
        host_id = (
            row.get("hostid")
            or row.get("hostname")
            or row.get("host")
            or row.get("hosturl")
            or f"host-{idx:02d}"
        )
        address = row.get("ip") or row.get("address") or row.get("hosturl") or row.get("host") or ""
        # When host_id came from IP/host cell used as address, keep id stable.
        if host_id == address and row.get("hostname"):
            host_id = row["hostname"]
        os_name = row.get("os") or row.get("operatingsystem") or row.get("osname") or ""
        services = _split_list(
            row.get("services")
            or row.get("discoveredservices")
            or row.get("discoveredservice")
            or ""
        )
        # Role column may be a role, not a service — keep both.
        roles = _split_list(row.get("role") or row.get("roles") or "")
        access = _split_list(row.get("access") or row.get("connection") or "")
        hosts.append(
            {
                "id": host_id,
                "hostname": row.get("hostname") or host_id,
                "address": address if address != host_id else row.get("ip") or "",
                "os": os_name,
                "roles": roles,
                "services": services,
                "connection": access,
                "notes": row.get("notes") or "",
            }
        )

    cred_rows = _parse_markdown_table(text, required_headers={"access", "service", "type"})
    credentials: list[dict[str, Any]] = []
    for row in cred_rows:
        if not (row.get("access") or row.get("service") or row.get("type")):
            continue
        if not (row.get("host") or row.get("hosturl") or row.get("url") or row.get("endpoint")):
            continue
        secret = (
            row.get("secretreference")
            or row.get("passwordtoken")
            or row.get("password")
            or row.get("token")
            or row.get("secret")
            or ""
        )
        secret_ref = ""
        has_secret = bool(secret)
        if secret.startswith(("vault://", "secret://", "env:", "file:")):
            secret_ref = secret
            has_secret = True
        elif secret:
            # Never keep plaintext in the normalized model — mark presence only.
            secret_ref = ""
            has_secret = True
        credentials.append(
            {
                "access": row.get("access") or row.get("service") or row.get("type") or "",
                "host": row.get("hosturl") or row.get("host") or row.get("url") or "",
                "port": row.get("port") or "",
                "username": row.get("username") or row.get("user") or "",
                "secret_ref": secret_ref,
                "database": row.get("database") or row.get("extra") or "",
                "has_secret": has_secret,
            }
        )

    return {
        "client": client,
        "hosts": hosts,
        "credentials": credentials,
        "questionnaires": [],
        "exceptions": [],
    }


def list_side_files(client_dir: Path) -> dict[str, list[str]]:
    """Discover optional questionnaires / exceptions / network files."""
    out: dict[str, list[str]] = {
        "questionnaires": [],
        "exceptions": [],
        "network": [],
        "credentials": [],
    }
    for name in ("QUESTIONNAIRE.md", "questionnaire.md"):
        if (client_dir / name).is_file():
            out["questionnaires"].append(name)
    qdir = client_dir / "questionnaires"
    if qdir.is_dir():
        for path in sorted(qdir.glob("*.md")):
            out["questionnaires"].append(str(path.relative_to(client_dir)))
    for name in ("EXCEPTIONS.md", "exceptions.md"):
        if (client_dir / name).is_file():
            out["exceptions"].append(name)
    for name in ("NETWORK.md", "network.md"):
        if (client_dir / name).is_file():
            out["network"].append(name)
    for name in ("CREDENTIALS.md", "credentials.md", "connection.md"):
        if (client_dir / name).is_file():
            out["credentials"].append(name)
    return out

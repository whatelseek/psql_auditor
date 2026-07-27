"""Normalize raw inventory documents into ``ClientInventory``."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auditor.domain.inventory import (
    ClientInventory,
    ConnectionType,
    CredentialReference,
    InventoryFact,
    InventoryHost,
    InventoryService,
    InventoryVersion,
    ValidationIssue,
    ValidationLevel,
)
from auditor.inventory.client_name import validate_client_name
from auditor.inventory.loaders import list_side_files

_OS_LINUX = {
    "ubuntu",
    "debian",
    "centos",
    "rhel",
    "rocky",
    "alma",
    "linux",
    "suse",
    "fedora",
}
_OS_WINDOWS = {"windows", "windows server", "win", "windowsserver"}

_SERVICE_ALIASES = {
    "ssh": "ssh",
    "sshd": "ssh",
    "openssh": "ssh",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "psql": "postgresql",
    "pg": "postgresql",
    "winrm": "winrm",
    "wsman": "winrm",
    "nginx": "nginx",
    "redis": "redis",
    "mysql": "mysql",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _content_hash(raw: dict[str, Any]) -> str:
    payload = json.dumps(raw, sort_keys=True, default=str, ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _norm_service(name: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "", (name or "").lower())
    return _SERVICE_ALIASES.get(key, key or name.strip().lower())


def _os_family(os_name: str) -> str:
    low = (os_name or "").strip().lower()
    if not low:
        return ""
    if any(tok in low for tok in _OS_WINDOWS) or low.startswith("win"):
        return "windows"
    if any(tok in low for tok in _OS_LINUX) or "linux" in low:
        return "linux"
    return "unknown"


def _connection_type(label: str) -> ConnectionType:
    low = (label or "").strip().lower()
    if low in {"ssh", "sftp", "os", "host"} or "ssh" in low:
        return "ssh"
    if low in {"winrm", "wsman"} or "winrm" in low:
        return "winrm"
    if low.startswith("postgres") or low in {"pg", "psql", "database", "db"}:
        return "postgresql"
    if low.startswith("mysql") or low in {"mariadb", "maria"}:
        return "mysql"
    if low.startswith("oracle") or low in {"ora", "oracledb"}:
        return "oracle"
    return "unknown"


def _parse_port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _valid_ip(value: str) -> bool:
    text = (value or "").strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def normalize_inventory(
    raw: dict[str, Any],
    *,
    client_name: str,
    source_path: Path | str,
    source_format: str,
    recorded_at: str | None = None,
) -> ClientInventory:
    """Build a validated ``ClientInventory`` from a raw loaded document."""
    client_id = validate_client_name(str(raw.get("client") or client_name))
    issues: list[ValidationIssue] = []
    for load_issue in raw.get("_load_issues") or []:
        if isinstance(load_issue, dict) and load_issue.get("code"):
            level_raw = str(load_issue.get("level") or "warning")
            level: ValidationLevel = (
                level_raw  # type: ignore[assignment]
                if level_raw in {"error", "warning", "information"}
                else "warning"
            )
            issues.append(
                ValidationIssue(
                    level=level,
                    code=str(load_issue["code"]),
                    message=str(load_issue.get("message") or load_issue["code"]),
                    host_id=load_issue.get("host_id"),
                    location=str(load_issue.get("location") or ""),
                )
            )
    hosts_raw = raw.get("hosts") or []
    if not isinstance(hosts_raw, list):
        issues.append(
            ValidationIssue(
                level="error",
                code="invalid_hosts",
                message="hosts must be a list",
                location="hosts",
            )
        )
        hosts_raw = []

    hosts: list[InventoryHost] = []
    seen_ids: set[str] = set()
    host_addresses: dict[str, str] = {}

    for index, item in enumerate(hosts_raw):
        if not isinstance(item, dict):
            issues.append(
                ValidationIssue(
                    level="error",
                    code="invalid_host_record",
                    message=f"host[{index}] must be an object",
                    location=f"hosts[{index}]",
                )
            )
            continue
        host_id = str(item.get("id") or item.get("host_id") or item.get("hostname") or "").strip()
        if not host_id:
            issues.append(
                ValidationIssue(
                    level="error",
                    code="missing_host_id",
                    message="host identifier is missing",
                    location=f"hosts[{index}]",
                )
            )
            continue
        if host_id.lower() in seen_ids:
            issues.append(
                ValidationIssue(
                    level="error",
                    code="duplicate_host",
                    message=f"duplicate host identifier {host_id!r}",
                    host_id=host_id,
                    location=f"hosts[{index}]",
                )
            )
            continue
        seen_ids.add(host_id.lower())

        address = str(item.get("address") or item.get("ip") or "").strip()
        hostname = str(item.get("hostname") or host_id).strip()
        asset_type = (
            str(item.get("asset_type") or item.get("type") or item.get("asset") or "server").strip()
            or "server"
        )
        vendor = str(item.get("vendor") or item.get("manufacturer") or "").strip()
        os_name = str(item.get("os") or item.get("os_name") or item.get("operating_system") or "")
        os_family = _os_family(os_name)
        # Infer network device typing from vendor/role keywords when omitted.
        roles_preview = item.get("roles") or item.get("role") or []
        if isinstance(roles_preview, str):
            roles_preview = [r.strip() for r in re.split(r"[,;/]+", roles_preview) if r.strip()]
        role_blob = " ".join(str(r).lower() for r in roles_preview)
        note_blob = str(item.get("notes") or "").lower()
        if asset_type.lower() == "server" and (
            vendor.lower() in {"cisco", "juniper", "aruba"}
            or "network" in role_blob
            or "switch" in role_blob
            or "router" in role_blob
            or "cisco" in note_blob
        ):
            asset_type = "network_device"
        if not vendor and "cisco" in f"{role_blob} {note_blob} {host_id}".lower():
            vendor = "cisco"
        if not os_name and asset_type.lower() not in {
            "network_device",
            "network",
            "switch",
            "router",
            "firewall",
        }:
            # IP/port/credentials-only hosts are valid; OS comes from discovery.
            issues.append(
                ValidationIssue(
                    level="information",
                    code="needs_discovery",
                    message=(
                        f"operating system missing for host {host_id}; "
                        "live read-only discovery is required before final "
                        "framework selection"
                    ),
                    host_id=host_id,
                    location=f"hosts[{index}].os",
                )
            )
        if address and not _valid_ip(address) and not re.search(r"[A-Za-z]", address):
            issues.append(
                ValidationIssue(
                    level="error",
                    code="invalid_ip",
                    message=f"invalid IP address {address!r}",
                    host_id=host_id,
                    location=f"hosts[{index}].address",
                )
            )
        if not address:
            issues.append(
                ValidationIssue(
                    level="warning",
                    code="missing_address",
                    message=f"host {host_id} has no network address",
                    host_id=host_id,
                    location=f"hosts[{index}].address",
                )
            )

        services_in = item.get("services") or []
        if isinstance(services_in, str):
            services_in = [s.strip() for s in re.split(r"[,;/]+", services_in) if s.strip()]
        roles_in = item.get("roles") or item.get("role") or []
        if isinstance(roles_in, str):
            roles_in = [r.strip() for r in re.split(r"[,;/]+", roles_in) if r.strip()]

        services: list[InventoryService] = []
        service_names: set[str] = set()
        for svc in services_in:
            if isinstance(svc, dict):
                name = _norm_service(str(svc.get("name") or ""))
                port = _parse_port(svc.get("port"))
            else:
                name = _norm_service(str(svc))
                port = None
            if not name:
                continue
            if name in service_names:
                issues.append(
                    ValidationIssue(
                        level="warning",
                        code="duplicate_service",
                        message=f"duplicate service {name!r} on {host_id}",
                        host_id=host_id,
                    )
                )
                continue
            service_names.add(name)
            if name == "postgresql" and port is None:
                port = 5432
            if name == "ssh" and port is None:
                port = 22
            if name == "winrm" and port is None:
                port = 5985
            services.append(
                InventoryService(
                    name=name,
                    port=port,
                    status="confirmed",
                    source="inventory",
                    confidence=1.0,
                )
            )

        # Contradictions: Windows + ssh-only linux stack, or postgresql on windows without note
        if os_family == "windows" and "postgresql" in service_names:
            issues.append(
                ValidationIssue(
                    level="warning",
                    code="unusual_service_os",
                    message=(
                        f"host {host_id} declares PostgreSQL on Windows; "
                        "verify inventory consistency"
                    ),
                    host_id=host_id,
                )
            )
        if os_family == "windows" and "ssh" in service_names and "winrm" not in service_names:
            issues.append(
                ValidationIssue(
                    level="information",
                    code="windows_ssh",
                    message=f"host {host_id} uses SSH on Windows (OpenSSH)",
                    host_id=host_id,
                )
            )
        if os_family == "linux" and "winrm" in service_names:
            issues.append(
                ValidationIssue(
                    level="error",
                    code="contradictory_service",
                    message=f"host {host_id} declares WinRM on Linux",
                    host_id=host_id,
                )
            )

        conn_in = item.get("connection") or item.get("connection_types") or item.get("access") or []
        if isinstance(conn_in, str):
            conn_in = [c.strip() for c in re.split(r"[,;/]+", conn_in) if c.strip()]
        connection_types: list[ConnectionType] = []
        for label in conn_in:
            kind = _connection_type(str(label))
            if kind == "unknown":
                issues.append(
                    ValidationIssue(
                        level="error",
                        code="unsupported_connection",
                        message=f"unsupported connection type {label!r} on {host_id}",
                        host_id=host_id,
                    )
                )
                continue
            if kind not in connection_types:
                connection_types.append(kind)
        # Infer connection from services when not declared.
        if not connection_types:
            if "winrm" in service_names or os_family == "windows":
                connection_types.append("winrm")
            if "ssh" in service_names or os_family == "linux":
                connection_types.append("ssh")
            if "postgresql" in service_names:
                connection_types.append("postgresql")

        facts = [
            InventoryFact(
                host_id=host_id,
                fact="os_family",
                value=os_family or "unknown",
                source="inventory",
                confidence=1.0 if os_family else 0.0,
            ),
            InventoryFact(
                host_id=host_id,
                fact="os_name",
                value=os_name,
                source="inventory",
                confidence=1.0 if os_name else 0.0,
            ),
        ]
        for svc in services:
            facts.append(
                InventoryFact(
                    host_id=host_id,
                    fact=f"{svc.name}_installed",
                    value=True,
                    source="inventory",
                    confidence=svc.confidence,
                )
            )

        host_addresses[host_id] = address
        hosts.append(
            InventoryHost(
                host_id=host_id,
                hostname=hostname,
                address=address,
                asset_type=asset_type,
                vendor=vendor,
                os_family=os_family,
                os_name=os_name,
                roles=tuple(str(r) for r in roles_in),
                services=tuple(services),
                connection_types=tuple(connection_types),
                notes=str(item.get("notes") or ""),
                facts=tuple(facts),
            )
        )

    credentials: list[CredentialReference] = []
    for index, cred in enumerate(raw.get("credentials") or []):
        if not isinstance(cred, dict):
            continue
        access = _connection_type(str(cred.get("access") or ""))
        host = str(cred.get("host") or "").strip()
        if not host:
            continue
        if access == "unknown":
            issues.append(
                ValidationIssue(
                    level="error",
                    code="unsupported_connection",
                    message=f"unsupported credential access type at credentials[{index}]",
                    location=f"credentials[{index}].access",
                )
            )
            continue
        port = _parse_port(cred.get("port"))
        if port is None and access in {"ssh", "winrm", "postgresql"}:
            issues.append(
                ValidationIssue(
                    level="warning",
                    code="missing_port",
                    message=f"missing port for {access} credential on {host}",
                    location=f"credentials[{index}].port",
                )
            )
        # Match credential host to inventory host ids / addresses.
        target_host_id = None
        for hid, addr in host_addresses.items():
            if host.lower() in {hid.lower(), addr.lower()}:
                target_host_id = hid
                break
        if target_host_id is None and hosts:
            issues.append(
                ValidationIssue(
                    level="warning",
                    code="credential_unknown_host",
                    message=f"credential host {host!r} does not match any inventory host",
                    location=f"credentials[{index}].host",
                )
            )
        if access == "postgresql" and not str(cred.get("database") or "").strip():
            issues.append(
                ValidationIssue(
                    level="warning",
                    code="incomplete_database_connection",
                    message=f"PostgreSQL credential for {host} missing database name",
                    host_id=target_host_id,
                    location=f"credentials[{index}].database",
                )
            )
        credentials.append(
            CredentialReference(
                access=access,
                host=host,
                port=port,
                username=str(cred.get("username") or ""),
                secret_ref=str(cred.get("secret_ref") or ""),
                database=str(cred.get("database") or ""),
                target_host_id=target_host_id,
                has_secret=bool(cred.get("has_secret")),
            )
        )

    side = (
        list_side_files(Path(source_path).parent)
        if source_path
        else {
            "questionnaires": [],
            "exceptions": [],
            "network": [],
            "credentials": [],
        }
    )
    questionnaires = tuple(
        str(x) for x in (raw.get("questionnaires") or side.get("questionnaires") or [])
    )
    exceptions = tuple(str(x) for x in (raw.get("exceptions") or side.get("exceptions") or []))

    content_hash = _content_hash(
        {
            "client": client_id,
            "hosts": [h.model_dump() for h in hosts],
            "credentials": [
                c.model_dump(exclude={"has_secret"}) | {"has_secret": c.has_secret}
                for c in credentials
            ],
            "questionnaires": list(questionnaires),
            "exceptions": list(exceptions),
        }
    )
    version = InventoryVersion(
        version_id=f"inv-{content_hash[:12]}",
        content_hash=content_hash,
        source_format=source_format,
        source_path=str(source_path or ""),
        recorded_at=recorded_at or _utc_now(),
    )

    databases = tuple(
        sorted(
            {
                f"{h.host_id}/postgresql"
                for h in hosts
                if any(s.name == "postgresql" for s in h.services)
            }
        )
    )

    return ClientInventory(
        client_id=client_id,
        hosts=tuple(hosts),
        databases=databases,
        applications=(),
        network_devices=tuple(str(x) for x in (raw.get("network_devices") or [])),
        credentials=tuple(credentials),
        questionnaires=questionnaires,
        exceptions=exceptions,
        facts=tuple(f for h in hosts for f in h.facts),
        version=version,
        issues=tuple(issues),
    )

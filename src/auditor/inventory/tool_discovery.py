"""ToolRegistry-driven discovery helpers (INPUT-005 POC).

Selects authorized SSH discovery tools from :class:`ToolRegistry` and executes
allow-listed probes via ``ssh_run``. WinRM/HTTP/TCP/SNMP adapters are out of
scope for this POC slice.
"""

from __future__ import annotations

import asyncio
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditor.domain.host_capability import HostCapabilitySnapshot
from auditor.inventory.discovery_evidence import assert_no_secrets, utc_now
from auditor.tool_registry import ToolManifest, ToolNotAuthorized, ToolRegistry, get_tool_registry

if TYPE_CHECKING:
    from auditor.domain.tool_result import ToolResult
    from auditor.inventory.collectors import CommandResult

# Registered SSH tools supported for discovery in this PR.
DISCOVERY_SSH_TOOL_IDS: frozenset[str] = frozenset({"ssh_run", "ssh_read_file"})

# Allow-listed atomic SSH probes (must pass ``is_approved_ssh_command``).
# INPUT-005 approved discovery set (read-only).
SSH_DISCOVERY_COMMANDS: tuple[str, ...] = (
    "hostname",
    "cat /etc/os-release",
    "uname -a",
    "uname -m",
    "ss -lntp",
    "ss -lntup",
    "systemctl list-units --type=service --state=running --no-pager",
    "command -v psql",
    "command -v postgres",
    "psql --version",
    "postgres --version",
    "systemctl is-active postgresql",
    # Supporting probes still on the SSH allow-list (process/service evidence).
    "ps -ef",
    "systemctl list-units --type=service --all --no-pager",
)


def select_discovery_tools(
    registry: ToolRegistry | None = None,
    *,
    transports: tuple[str, ...] = ("ssh",),
) -> list[ToolManifest]:
    """Return registry-authorized discovery tools (SSH-only in this POC)."""
    registry = registry or get_tool_registry()
    selected: list[ToolManifest] = []
    for tool in registry.authorized_tools(transports=transports):
        if tool.id in DISCOVERY_SSH_TOOL_IDS:
            selected.append(tool)
    return selected


def require_ssh_discovery_tool(registry: ToolRegistry | None = None) -> ToolManifest:
    """Fail closed unless ``ssh_run`` is authorized for discovery."""
    registry = registry or get_tool_registry()
    tools = {t.id: t for t in select_discovery_tools(registry)}
    if "ssh_run" not in tools:
        raise ToolNotAuthorized(
            "ssh_run is not available for discovery under the active capability policy",
            code="discovery_tool_unavailable",
        )
    return registry.require_authorized("ssh_run")


def parse_postgres_version(text: str) -> str:
    """Extract a PostgreSQL version token from ``psql --version`` style output."""
    match = re.search(
        r"(?i)(?:psql|postgres(?:ql)?)\s*(?:\([^)]*\))?\s*(\d+(?:\.\d+)*)",
        text or "",
    )
    if match:
        return match.group(1)
    match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", text or "")
    return match.group(1) if match else ""


def _stdout_from_tool_output(output: str) -> str:
    text = output or ""
    if "stdout:\n" in text:
        rest = text.split("stdout:\n", 1)[1]
        if "\nstderr:\n" in rest:
            rest = rest.split("\nstderr:\n", 1)[0]
        return rest
    return text


def _stderr_from_tool_output(output: str) -> str:
    text = output or ""
    if "\nstderr:\n" in text:
        return text.split("\nstderr:\n", 1)[1]
    return ""


def tool_result_to_command_result(command: str, result: ToolResult) -> CommandResult:
    """Map a normalized ToolResult into discovery CommandResult."""
    from auditor.inventory.collectors import (
        ERROR_AUTHENTICATION_FAILED,
        ERROR_COMMAND_TIMEOUT,
        ERROR_CONNECTION_TIMEOUT,
        ERROR_DISCOVERY_FAILED,
        ERROR_HOST_UNREACHABLE,
        CommandResult,
    )

    status = (result.status or "").lower()
    error = (result.error or "").strip()
    error_code = ""
    if status in {"unauthorized", "denied"}:
        error_code = (
            ERROR_AUTHENTICATION_FAILED if "auth" in error.lower() else ERROR_DISCOVERY_FAILED
        )
        if "timeout" in error.lower():
            error_code = ERROR_CONNECTION_TIMEOUT
        if "unreachable" in error.lower() or "refused" in error.lower():
            error_code = ERROR_HOST_UNREACHABLE
    elif status == "timeout":
        error_code = ERROR_COMMAND_TIMEOUT
    elif status == "error" and error:
        low = error.lower()
        if "auth" in low or "permission denied" in low:
            error_code = ERROR_AUTHENTICATION_FAILED
        elif "timeout" in low:
            error_code = ERROR_CONNECTION_TIMEOUT
        elif "unreachable" in low or "refused" in low or "no route" in low:
            error_code = ERROR_HOST_UNREACHABLE
        elif "hostkey" in low or "not trusted" in low:
            error_code = ERROR_AUTHENTICATION_FAILED

    if status in {"error", "timeout", "denied", "unauthorized"} and not (
        result.exit_code in {0, None}
        and _stdout_from_tool_output(result.output or "").strip()
        and "stdout:\n" in (result.output or "")
    ):
        # Prefer structured error fields; avoid treating SSH exception text as facts.
        stdout = (
            _stdout_from_tool_output(result.output or "")
            if "stdout:\n" in (result.output or "")
            else ""
        )
        stderr = _stderr_from_tool_output(result.output or "") or (result.output or "")
        return CommandResult(
            command=command,
            exit_code=result.exit_code,
            stdout=stdout,
            stderr=stderr if stdout else (error or result.output or status),
            error=error or (result.output or status),
            error_code=error_code or ERROR_DISCOVERY_FAILED,
        )

    return CommandResult(
        command=command,
        exit_code=result.exit_code,
        stdout=_stdout_from_tool_output(result.output or ""),
        stderr=_stderr_from_tool_output(result.output or ""),
        error=error,
        error_code=error_code,
    )


@dataclass(slots=True)
class RegistrySshTransport:
    """ShellTransport backed by ToolRegistry-authorized ``invoke_ssh_run``."""

    command_timeout: float = 30.0
    registry: ToolRegistry | None = None

    def run(self, command: str, *, timeout: float) -> CommandResult:
        from auditor.inventory.collectors import (
            ERROR_DISCOVERY_FAILED,
            DiscoveryTransportError,
        )

        require_ssh_discovery_tool(self.registry)

        async def _invoke() -> ToolResult:
            from auditor.domain.tool_result import ToolResult as _ToolResult
            from auditor.tools.ssh import invoke_ssh_run

            result: _ToolResult = await invoke_ssh_run(
                command,
                timeout_seconds=int(timeout or self.command_timeout),
            )
            return result

        try:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                tool_result = asyncio.run(_invoke())
            else:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    tool_result = pool.submit(lambda: asyncio.run(_invoke())).result()
        except ToolNotAuthorized:
            raise
        except Exception as exc:  # noqa: BLE001
            raise DiscoveryTransportError(str(exc), code=ERROR_DISCOVERY_FAILED) from exc
        return tool_result_to_command_result(command, tool_result)


def build_host_capability_snapshot(
    *,
    host_id: str,
    client_id: str = "",
    inventory_version_id: str = "",
    asset_type: str = "server",
    os_name: str = "",
    os_family: str = "",
    os_version: str = "",
    ssh_access: bool = False,
    ssh_status: str = "",
    running_services: list[str] | None = None,
    listening_ports: list[int] | None = None,
    postgresql_present: bool = False,
    postgresql_version: str = "",
    postgresql_status: str = "",
    transport: str = "ssh",
    tool_ids: tuple[str, ...] | list[str] = (),
    collector: str = "ssh",
    confidence: str = "high",
    evidence_ref: str = "",
    evidence_refs: list[str] | None = None,
    collected_at: str = "",
    limitations: list[str] | None = None,
    error: str = "",
    error_code: str = "",
    tool_catalog_hash: str = "",
    capability_policy_hash: str = "",
) -> HostCapabilitySnapshot:
    """Build a HostCapabilitySnapshot from discovery facts."""
    from auditor.domain.host_capability import (
        SnapshotAccessMethod,
        SnapshotOsInfo,
        SnapshotTechnology,
    )

    distribution = ""
    pretty = os_name or ""
    low = pretty.lower()
    for token in ("ubuntu", "debian", "centos", "rhel", "rocky", "fedora", "suse", "windows"):
        if token in low:
            distribution = token
            break
    if not distribution and os_family:
        distribution = os_family

    if not ssh_status:
        if ssh_access:
            ssh_status = "connected"
        elif error_code in {
            "authentication_failed",
            "host_unreachable",
            "connection_timeout",
        }:
            ssh_status = "failed"
        else:
            ssh_status = "unavailable"

    technologies: list[SnapshotTechnology] = []
    if postgresql_present or postgresql_status:
        status = postgresql_status or ("confirmed" if postgresql_present else "absent")
        evidence = ["discovery"]
        if status == "suspected":
            evidence = ["port=5432"]
        elif status == "absent":
            evidence = ["no_postgresql_signal"]
        technologies.append(
            SnapshotTechnology(
                technology_id="postgresql",
                status=status,
                version=postgresql_version,
                evidence=evidence,
            )
        )
    elif os_family and not error_code:
        technologies.append(
            SnapshotTechnology(
                technology_id="postgresql",
                status="absent",
                evidence=["no_postgresql_signal"],
            )
        )

    refs = list(evidence_refs or [])
    if evidence_ref and evidence_ref not in refs:
        refs.append(evidence_ref)

    hashes = {
        "tool_catalog_hash": tool_catalog_hash,
        "capability_policy_hash": capability_policy_hash,
    }
    if not tool_catalog_hash or not capability_policy_hash:
        try:
            hashes.update(get_tool_registry().snapshot_hashes())
        except Exception:  # noqa: BLE001
            pass

    return HostCapabilitySnapshot(
        schema="host_capability_snapshot.v1",
        client_id=client_id,
        host_id=host_id,
        inventory_version_id=inventory_version_id,
        asset_type=asset_type or "server",
        platform=os_family or distribution or "",
        os=SnapshotOsInfo(
            family=os_family or "",
            distribution=distribution,
            version=os_version or "",
        ),
        access={
            "ssh": SnapshotAccessMethod(available=ssh_access, status=ssh_status),
        },
        technologies=technologies,
        listening_ports=list(listening_ports or []),
        running_services=list(running_services or []),
        tool_catalog_hash=hashes.get("tool_catalog_hash", ""),
        capability_policy_hash=hashes.get("capability_policy_hash", ""),
        evidence_refs=refs,
        tool_ids=tuple(tool_ids),
        collector=collector,
        confidence=confidence,
        collected_at=collected_at or utc_now(),
        limitations=list(limitations or []),
        error=error,
        error_code=error_code,
        os_name=os_name,
        os_family=os_family,
        os_version=os_version,
        ssh_access=ssh_access,
        postgresql_present=postgresql_present,
        postgresql_version=postgresql_version,
        evidence_ref=evidence_ref,
        transport=transport,
    )


def persist_host_capability_snapshot(
    snapshot: HostCapabilitySnapshot,
    *,
    artifacts_root: Path | str,
    client_slug: str,
    inventory_version_id: str,
    known_secrets: list[str] | None = None,
) -> Path:
    """Persist a capability snapshot under the host preflight directory."""
    # Ensure identity fields are populated for the on-disk document.
    if not snapshot.client_id:
        snapshot.client_id = client_slug
    if not snapshot.inventory_version_id:
        snapshot.inventory_version_id = inventory_version_id

    root = (
        Path(artifacts_root) / client_slug / "preflight" / inventory_version_id / snapshot.host_id
    )
    root.mkdir(parents=True, exist_ok=True)
    path = root / "capability_snapshot.json"
    payload = snapshot.to_dict()
    payload["written_at"] = utc_now()
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    assert_no_secrets(text, known_secrets=known_secrets or [])
    path.write_text(text, encoding="utf-8")
    return path


def technologies_from_detections(
    detections: list[Any],
    host_id: str,
) -> list[Any]:
    """Map deterministic TechnologyDetection rows for one host into snapshot techs."""
    from auditor.domain.host_capability import SnapshotTechnology

    techs: list[SnapshotTechnology] = []
    for det in detections:
        target = getattr(det, "target_id", "") or ""
        if target != host_id and not target.startswith(f"{host_id}/"):
            continue
        techs.append(
            SnapshotTechnology(
                technology_id=str(getattr(det, "technology_id", "")),
                status=str(getattr(det, "status", "unknown")),
                version="",
                evidence=list(getattr(det, "evidence", ()) or ()),
            )
        )
    return techs


def sync_capability_snapshots_from_detections(
    inventory: Any,
    detections: list[Any],
    *,
    artifacts_root: Path | str,
) -> list[Path]:
    """Rewrite HostCapabilitySnapshot.technologies from detect_technologies output.

    Ensures snapshot technology statuses match framework-selection evidence
    (port-only → suspected, strong evidence → confirmed, none → absent).
    """
    from auditor.domain.host_capability import (
        SnapshotAccessMethod,
        SnapshotOsInfo,
        SnapshotTechnology,
    )
    from auditor.domain.inventory import ClientInventory

    if not isinstance(inventory, ClientInventory):
        return []

    root = Path(artifacts_root)
    written: list[Path] = []
    version_id = inventory.version.version_id
    for host in inventory.hosts:
        snap_path = root / inventory.client_id / "preflight" / version_id / host.host_id
        snap_path.mkdir(parents=True, exist_ok=True)
        path = snap_path / "capability_snapshot.json"
        techs = technologies_from_detections(detections, host.host_id)

        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            snapshot = HostCapabilitySnapshot(
                schema=str(data.get("schema") or "host_capability_snapshot.v1"),
                client_id=str(data.get("client_id") or inventory.client_id),
                host_id=host.host_id,
                inventory_version_id=str(data.get("inventory_version_id") or version_id),
                asset_type=str(data.get("asset_type") or host.asset_type or "server"),
                platform=str(data.get("platform") or host.os_family or host.vendor or ""),
                os=SnapshotOsInfo(
                    family=str((data.get("os") or {}).get("family") or host.os_family or ""),
                    distribution=str((data.get("os") or {}).get("distribution") or ""),
                    version=str((data.get("os") or {}).get("version") or ""),
                ),
                access={
                    name: SnapshotAccessMethod(
                        available=bool((method or {}).get("available")),
                        status=str((method or {}).get("status") or "unavailable"),
                    )
                    for name, method in (data.get("access") or {}).items()
                },
                technologies=techs,
                listening_ports=list(data.get("listening_ports") or []),
                running_services=list(data.get("running_services") or []),
                tool_catalog_hash=str(data.get("tool_catalog_hash") or ""),
                capability_policy_hash=str(data.get("capability_policy_hash") or ""),
                evidence_refs=list(data.get("evidence_refs") or []),
                tool_ids=tuple(data.get("tool_ids") or ()),
                collector=str(data.get("collector") or ""),
                confidence=str(data.get("confidence") or "low"),
                collected_at=str(data.get("collected_at") or utc_now()),
                limitations=list(data.get("limitations") or []),
                error=str(data.get("error") or ""),
                error_code=str(data.get("error_code") or ""),
                os_name=str(data.get("os_name") or host.os_name or ""),
                os_family=str(data.get("os_family") or host.os_family or ""),
                os_version=str(data.get("os_version") or ""),
                ssh_access=bool(data.get("ssh_access")),
                postgresql_present=any(
                    isinstance(t, SnapshotTechnology)
                    and t.technology_id == "postgresql"
                    and t.status == "confirmed"
                    for t in techs
                ),
                transport=str(data.get("transport") or ""),
            )
        else:
            vendor = (host.vendor or "").lower()
            snapshot = HostCapabilitySnapshot(
                client_id=inventory.client_id,
                host_id=host.host_id,
                inventory_version_id=version_id,
                asset_type=host.asset_type or "server",
                platform=host.os_family or host.vendor or "",
                os=SnapshotOsInfo(family=host.os_family or ""),
                access={
                    "ssh": SnapshotAccessMethod(
                        available=False,
                        status="unavailable",
                    )
                },
                technologies=techs,
                collector="unsupported" if host.is_unsupported_network_device else "inventory",
                confidence="low" if host.is_unsupported_network_device else "medium",
                collected_at=utc_now(),
                limitations=(
                    [f"missing:{vendor or 'cisco'}.cli.read"]
                    if host.is_unsupported_network_device
                    else []
                ),
                error=(
                    f"unsupported asset_type={host.asset_type or 'network_device'} "
                    f"vendor={host.vendor or 'unknown'}"
                    if host.is_unsupported_network_device
                    else ""
                ),
                error_code="unsupported_transport" if host.is_unsupported_network_device else "",
                os_name=host.os_name,
                os_family=host.os_family,
            )
            try:
                hashes = get_tool_registry().snapshot_hashes()
                snapshot.tool_catalog_hash = hashes.get("tool_catalog_hash", "")
                snapshot.capability_policy_hash = hashes.get("capability_policy_hash", "")
            except Exception:  # noqa: BLE001
                pass

        written.append(
            persist_host_capability_snapshot(
                snapshot,
                artifacts_root=root,
                client_slug=inventory.client_id,
                inventory_version_id=version_id,
            )
        )
    return written

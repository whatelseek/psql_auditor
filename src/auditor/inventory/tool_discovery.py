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
SSH_DISCOVERY_COMMANDS: tuple[str, ...] = (
    "hostname",
    "cat /etc/os-release",
    "uname -a",
    "ss -lntup",
    "netstat -lntup",
    "systemctl list-units --type=service --state=running --no-pager",
    "systemctl list-units --type=service --all --no-pager",
    "command -v psql",
    "command -v postgres",
    "ps -ef",
    "psql --version",
    "postgres --version",
    "dpkg-query -W postgresql",
    "rpm -q postgresql",
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
    os_name: str = "",
    os_family: str = "",
    os_version: str = "",
    ssh_access: bool = False,
    running_services: list[str] | None = None,
    listening_ports: list[int] | None = None,
    postgresql_present: bool = False,
    postgresql_version: str = "",
    transport: str = "ssh",
    tool_ids: tuple[str, ...] | list[str] = (),
    collector: str = "ssh",
    confidence: str = "high",
    evidence_ref: str = "",
    collected_at: str = "",
    limitations: list[str] | None = None,
    error: str = "",
    error_code: str = "",
) -> HostCapabilitySnapshot:
    """Build a HostCapabilitySnapshot from discovery facts."""
    return HostCapabilitySnapshot(
        host_id=host_id,
        os_name=os_name,
        os_family=os_family,
        os_version=os_version,
        ssh_access=ssh_access,
        running_services=list(running_services or []),
        listening_ports=list(listening_ports or []),
        postgresql_present=postgresql_present,
        postgresql_version=postgresql_version,
        transport=transport,
        tool_ids=tuple(tool_ids),
        collector=collector,
        confidence=confidence,
        evidence_ref=evidence_ref,
        collected_at=collected_at or utc_now(),
        limitations=list(limitations or []),
        error=error,
        error_code=error_code,
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
    root = (
        Path(artifacts_root) / client_slug / "preflight" / inventory_version_id / snapshot.host_id
    )
    root.mkdir(parents=True, exist_ok=True)
    path = root / "capability_snapshot.json"
    payload: dict[str, Any] = {
        "schema": "host_capability_snapshot.v1",
        "snapshot": snapshot.to_dict(),
        "written_at": utc_now(),
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    assert_no_secrets(text, known_secrets=known_secrets or [])
    path.write_text(text, encoding="utf-8")
    return path

"""Registered TCP connect discovery adapter (TOOL-004 / INPUT-005).

Direct ``socket`` usage is confined to this adapter. Discovery workflows must
invoke TCP checks only through :class:`~auditor.tool_registry.ToolRegistry`.
"""

from __future__ import annotations

import hashlib
import socket
from datetime import datetime, timezone
from typing import Any

from auditor.domain.tool_result import ToolProvenance, ToolResult, ToolTargetRef
from auditor.runtime_target import effective_settings
from auditor.tool_registry import get_tool_registry

_TOOL_ID = "tcp_connect"
_TOOL_VERSION = "1.0.0"
_MAX_PORTS = 20


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _authorize() -> ToolResult | None:
    try:
        get_tool_registry().require_authorized(_TOOL_ID)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            status="unauthorized",
            error=str(exc),
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=_utc_now_iso(),
            finished_at=_utc_now_iso(),
        )
    return None


async def invoke_tcp_connect(
    ports: list[int] | tuple[int, ...] | None = None,
    *,
    timeout_seconds: float | None = None,
    host: str | None = None,
    **_kwargs: Any,
) -> ToolResult:
    """Probe explicitly approved TCP ports on the inventory-resolved host.

    ``host`` overrides are ignored — the active inventory/run context supplies
    the target. Ports are capped at 20 and must be in 1..65535.
    """
    denied = _authorize()
    if denied is not None:
        return denied

    started = _utc_now_iso()
    settings = effective_settings()
    target_host = (settings.ssh_host or "").strip()
    if not target_host:
        # Fall back to generic host from settings if SSH host unset (TCP-only assets).
        target_host = str(getattr(settings, "tcp_host", "") or "").strip()
    if host and host.strip() and host.strip() != target_host:
        return ToolResult(
            status="denied",
            error="target override is not allowed; host is resolved from inventory context",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
            arguments={"ports": list(ports or [])},
        )
    if not target_host:
        return ToolResult(
            status="error",
            error="no inventory host address available for tcp.connect",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )

    cleaned: list[int] = []
    for raw in ports or []:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in cleaned:
            cleaned.append(port)
        if len(cleaned) >= _MAX_PORTS:
            break
    if not cleaned:
        return ToolResult(
            status="denied",
            error="tcp.connect requires 1..20 explicit ports from inventory/framework metadata",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
            arguments={"ports": []},
        )

    timeout = float(timeout_seconds if timeout_seconds is not None else 3.0)
    results: list[str] = []
    for port in cleaned:
        status = _probe(target_host, port, timeout)
        results.append(f"{port}={status}")

    hashes = {}
    try:
        hashes = get_tool_registry().snapshot_hashes()
    except Exception:  # noqa: BLE001
        pass

    return ToolResult(
        status="ok",
        output="\n".join(results),
        tool_id=_TOOL_ID,
        tool_version=_TOOL_VERSION,
        target=ToolTargetRef(host=target_host, transport="tcp", label="tcp_connect"),
        started_at=started,
        finished_at=_utc_now_iso(),
        arguments={"ports": cleaned},
        provenance=ToolProvenance(
            source="tool_registry",
            tool_catalog_hash=hashes.get("tool_catalog_hash", ""),
            capability_policy_hash=hashes.get("capability_policy_hash", ""),
            command_hash=hashlib.sha256(",".join(map(str, cleaned)).encode()).hexdigest()[:16],
            policy_decision="allow",
        ),
    )


def _probe(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except TimeoutError:
        return "filtered"
    except OSError:
        return "closed"


def normalize_tcp_connect_result(
    result: ToolResult,
    *,
    host_id: str,
    evidence_ref: str = "",
) -> list[dict[str, object]]:
    """Convert ToolResult output into normalized port.* facts."""
    if result.status != "ok":
        return []
    facts: list[dict[str, object]] = []
    for line in (result.output or "").splitlines():
        if "=" not in line:
            continue
        port_s, status = line.split("=", 1)
        try:
            port = int(port_s)
        except ValueError:
            continue
        facts.append(
            {
                "host_id": host_id,
                "fact": f"port.{port}.status",
                "value": status.strip(),
                "confidence": 0.7 if status.strip() == "open" else 0.5,
                "source": "tcp_connect",
                "evidence_ref": evidence_ref or f"evidence://preflight/{host_id}/tcp-{port}",
            }
        )
    return facts

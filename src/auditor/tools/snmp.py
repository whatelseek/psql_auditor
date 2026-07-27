"""Registered SNMP GET/WALK discovery adapters (TOOL-005 / INPUT-005).

Uses a pluggable transport so unit tests can inject a fake without importing
SNMP libraries into discovery workflows. Production uses a bounded stub that
refuses SET and requires runtime credentials from inventory context.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from auditor.domain.tool_result import ToolProvenance, ToolResult, ToolTargetRef
from auditor.runtime_target import effective_settings
from auditor.tool_registry import get_tool_registry

_GET_ID = "snmp_get"
_WALK_ID = "snmp_walk"
_VERSION = "1.0.0"
_MAX_OIDS = 30
_MAX_WALK = 100

# Default allow-listed OID prefixes (sysDescr / sysObjectID / entPhysical).
_ALLOWED_OID_PREFIXES = (
    "1.3.6.1.2.1.1.",
    "1.3.6.1.2.1.47.",
    "1.3.6.1.4.1.9.",  # Cisco enterprise (read-only identity)
)


class SnmpTransport(Protocol):
    def get(self, host: str, oids: list[str]) -> dict[str, str]: ...

    def walk(self, host: str, oid_prefix: str, *, max_rows: int) -> dict[str, str]: ...


_transport_factory: Callable[[], SnmpTransport] | None = None


def set_snmp_transport_factory(factory: Callable[[], SnmpTransport] | None) -> None:
    """Test hook to inject a fake SNMP transport."""
    global _transport_factory
    _transport_factory = factory


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _authorize(tool_id: str) -> ToolResult | None:
    try:
        get_tool_registry().require_authorized(tool_id)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            status="unauthorized",
            error=str(exc),
            tool_id=tool_id,
            tool_version=_VERSION,
            started_at=_utc_now_iso(),
            finished_at=_utc_now_iso(),
        )
    return None


def _validate_oids(oids: list[str]) -> list[str] | ToolResult:
    cleaned: list[str] = []
    for oid in oids:
        text = str(oid).strip()
        if not text or not text.replace(".", "").isdigit():
            continue
        if not any(
            text.startswith(prefix.rstrip(".")) or text.startswith(prefix)
            for prefix in _ALLOWED_OID_PREFIXES
        ):
            return ToolResult(
                status="denied",
                error=f"OID {text!r} is not allowed by capability policy",
                tool_id=_GET_ID,
                tool_version=_VERSION,
                started_at=_utc_now_iso(),
                finished_at=_utc_now_iso(),
            )
        if text not in cleaned:
            cleaned.append(text)
        if len(cleaned) >= _MAX_OIDS:
            break
    if not cleaned:
        return ToolResult(
            status="denied",
            error="snmp.get requires 1..30 allow-listed OIDs",
            tool_id=_GET_ID,
            tool_version=_VERSION,
            started_at=_utc_now_iso(),
            finished_at=_utc_now_iso(),
        )
    return cleaned


class _RefuseSetTransport:
    """Default transport: no live SNMP; returns empty unless factory injected."""

    def get(self, host: str, oids: list[str]) -> dict[str, str]:
        raise RuntimeError(
            "no SNMP transport configured; inject set_snmp_transport_factory for tests "
            "or configure a production adapter"
        )

    def walk(self, host: str, oid_prefix: str, *, max_rows: int) -> dict[str, str]:
        raise RuntimeError("no SNMP transport configured")


def _transport() -> SnmpTransport:
    if _transport_factory is not None:
        return _transport_factory()
    return _RefuseSetTransport()


async def invoke_snmp_get(
    oids: list[str] | tuple[str, ...] | None = None,
    *,
    host: str | None = None,
    **_kwargs: Any,
) -> ToolResult:
    """SNMP GET for allow-listed OIDs. Credentials never enter the result."""
    denied = _authorize(_GET_ID)
    if denied is not None:
        return denied
    started = _utc_now_iso()
    settings = effective_settings()
    target_host = (settings.ssh_host or "").strip()
    if host and host.strip() and host.strip() != target_host:
        return ToolResult(
            status="denied",
            error="target override is not allowed",
            tool_id=_GET_ID,
            tool_version=_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    if not target_host:
        return ToolResult(
            status="error",
            error="no inventory host address available for snmp.get",
            tool_id=_GET_ID,
            tool_version=_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    validated = _validate_oids(list(oids or []))
    if isinstance(validated, ToolResult):
        return validated

    try:
        values = _transport().get(target_host, validated)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            status="error",
            error=str(exc),
            tool_id=_GET_ID,
            tool_version=_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
            arguments={"oids": validated},
        )

    # Never include community/auth material.
    lines = [f"{oid}={values.get(oid, '')}" for oid in validated]
    hashes = {}
    try:
        hashes = get_tool_registry().snapshot_hashes()
    except Exception:  # noqa: BLE001
        pass
    return ToolResult(
        status="ok",
        output="\n".join(lines),
        tool_id=_GET_ID,
        tool_version=_VERSION,
        target=ToolTargetRef(host=target_host, transport="snmp", label="snmp_get"),
        started_at=started,
        finished_at=_utc_now_iso(),
        arguments={"oids": validated},
        provenance=ToolProvenance(
            source="tool_registry",
            tool_catalog_hash=hashes.get("tool_catalog_hash", ""),
            capability_policy_hash=hashes.get("capability_policy_hash", ""),
            command_hash=hashlib.sha256(",".join(validated).encode()).hexdigest()[:16],
            policy_decision="allow",
        ),
    )


async def invoke_snmp_walk(
    oid_prefix: str = "1.3.6.1.2.1.1",
    *,
    max_rows: int = _MAX_WALK,
    host: str | None = None,
    **_kwargs: Any,
) -> ToolResult:
    """Bounded SNMP WALK. SET is not implemented and cannot be requested."""
    denied = _authorize(_WALK_ID)
    if denied is not None:
        return denied
    started = _utc_now_iso()
    if "set" in str(oid_prefix).lower():
        return ToolResult(
            status="denied",
            error="SNMP SET is not permitted",
            tool_id=_WALK_ID,
            tool_version=_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    settings = effective_settings()
    target_host = (settings.ssh_host or "").strip()
    if not target_host:
        return ToolResult(
            status="error",
            error="no inventory host address available for snmp.walk",
            tool_id=_WALK_ID,
            tool_version=_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    prefix = str(oid_prefix).strip()
    if not any(
        prefix.startswith(p.rstrip(".")) or prefix.startswith(p) for p in _ALLOWED_OID_PREFIXES
    ):
        return ToolResult(
            status="denied",
            error=f"OID prefix {prefix!r} is not allowed",
            tool_id=_WALK_ID,
            tool_version=_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    limit = max(1, min(int(max_rows or _MAX_WALK), _MAX_WALK))
    try:
        values = _transport().walk(target_host, prefix, max_rows=limit)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            status="error",
            error=str(exc),
            tool_id=_WALK_ID,
            tool_version=_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    lines = [f"{oid}={val}" for oid, val in list(values.items())[:limit]]
    return ToolResult(
        status="ok",
        output="\n".join(lines),
        tool_id=_WALK_ID,
        tool_version=_VERSION,
        target=ToolTargetRef(host=target_host, transport="snmp", label="snmp_walk"),
        started_at=started,
        finished_at=_utc_now_iso(),
        arguments={"oid_prefix": prefix, "max_rows": limit},
    )


def normalize_snmp_get_result(
    result: ToolResult,
    *,
    host_id: str,
    evidence_ref: str = "",
) -> list[dict[str, object]]:
    """Map common identity OIDs into asset/os normalized facts."""
    if result.status != "ok":
        return []
    ref = evidence_ref or f"evidence://preflight/{host_id}/snmp-001"
    facts: list[dict[str, object]] = [
        {
            "host_id": host_id,
            "fact": "access.snmp.available",
            "value": True,
            "confidence": 1.0,
            "source": "snmp_get",
            "evidence_ref": ref,
        }
    ]
    blob = (result.output or "").lower()
    if "cisco" in blob:
        facts.append(
            {
                "host_id": host_id,
                "fact": "asset.vendor",
                "value": "cisco",
                "confidence": 1.0,
                "source": "snmp_get",
                "evidence_ref": ref,
            }
        )
        facts.append(
            {
                "host_id": host_id,
                "fact": "os.family",
                "value": "ios_xe" if "ios-xe" in blob or "ios_xe" in blob else "ios",
                "confidence": 0.9,
                "source": "snmp_get",
                "evidence_ref": ref,
            }
        )
    # sysDescr line
    for line in (result.output or "").splitlines():
        if line.startswith("1.3.6.1.2.1.1.1.0="):
            descr = line.split("=", 1)[1].strip()
            facts.append(
                {
                    "host_id": host_id,
                    "fact": "asset.model",
                    "value": descr[:120],
                    "confidence": 0.8,
                    "source": "snmp_get",
                    "evidence_ref": ref,
                }
            )
    return facts

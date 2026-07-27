"""Registered HTTP GET/HEAD discovery adapter (TOOL-003 / INPUT-005)."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from auditor.domain.tool_result import ToolProvenance, ToolResult, ToolTargetRef
from auditor.runtime_target import effective_settings
from auditor.tool_registry import get_tool_registry

_TOOL_ID = "http_get"
_TOOL_VERSION = "1.0.0"
_MAX_BODY = 16384
_BLOCKED_URL = re.compile(r"(?i)(https?://[^/@]*:[^/@]*@)|([?&](token|api_key|password|secret)=)")


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


async def invoke_http_get(
    *,
    scheme: str = "https",
    port: int | None = None,
    path: str = "/",
    method: str = "GET",
    timeout_seconds: float | None = None,
    host: str | None = None,
    **_kwargs: Any,
) -> ToolResult:
    """Perform a read-only HTTP GET/HEAD against the inventory-resolved host."""
    denied = _authorize()
    if denied is not None:
        return denied

    started = _utc_now_iso()
    settings = effective_settings()
    target_host = (settings.ssh_host or "").strip()
    if host and host.strip() and host.strip() != target_host:
        return ToolResult(
            status="denied",
            error="target override is not allowed; host is resolved from inventory context",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    if not target_host:
        return ToolResult(
            status="error",
            error="no inventory host address available for http.get",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )

    method_u = (method or "GET").upper()
    if method_u not in {"GET", "HEAD"}:
        return ToolResult(
            status="denied",
            error="http.get allows only GET or HEAD",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    scheme_l = (scheme or "https").lower()
    if scheme_l not in {"http", "https"}:
        return ToolResult(
            status="denied",
            error="scheme must be http or https",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    safe_path = path or "/"
    if not safe_path.startswith("/"):
        safe_path = "/" + safe_path
    netloc = target_host if port is None else f"{target_host}:{int(port)}"
    url = f"{scheme_l}://{netloc}{safe_path}"
    if _BLOCKED_URL.search(url):
        return ToolResult(
            status="denied",
            error="credentials embedded in URL are forbidden",
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )

    timeout = float(timeout_seconds if timeout_seconds is not None else 10.0)
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=3,
        ) as client:
            response = await client.request(method_u, url)
            # Redirects must not leave approved host scope.
            final = urlparse(str(response.url))
            if final.hostname and final.hostname.lower() != target_host.lower():
                return ToolResult(
                    status="denied",
                    error="redirect left approved inventory host scope",
                    tool_id=_TOOL_ID,
                    tool_version=_TOOL_VERSION,
                    started_at=started,
                    finished_at=_utc_now_iso(),
                    arguments={
                        "scheme": scheme_l,
                        "port": port,
                        "path": safe_path,
                        "method": method_u,
                    },
                )
            body = response.text[:_MAX_BODY]
            server = response.headers.get("server", "")
            # Never persist authorization headers / cookies.
            output = f"status={response.status_code}\nserver={server}\nbody_prefix={body[:500]}"
    except httpx.TimeoutException as exc:
        return ToolResult(
            status="timeout",
            error=str(exc),
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            status="error",
            error=str(exc),
            tool_id=_TOOL_ID,
            tool_version=_TOOL_VERSION,
            started_at=started,
            finished_at=_utc_now_iso(),
        )

    hashes = {}
    try:
        hashes = get_tool_registry().snapshot_hashes()
    except Exception:  # noqa: BLE001
        pass

    return ToolResult(
        status="ok",
        output=output,
        tool_id=_TOOL_ID,
        tool_version=_TOOL_VERSION,
        target=ToolTargetRef(host=target_host, port=port, transport="http", label="http_get"),
        started_at=started,
        finished_at=_utc_now_iso(),
        arguments={"scheme": scheme_l, "port": port, "path": safe_path, "method": method_u},
        provenance=ToolProvenance(
            source="tool_registry",
            tool_catalog_hash=hashes.get("tool_catalog_hash", ""),
            capability_policy_hash=hashes.get("capability_policy_hash", ""),
            command_hash=hashlib.sha256(url.encode()).hexdigest()[:16],
            policy_decision="allow",
        ),
        exit_code=0,
    )


def normalize_http_get_result(
    result: ToolResult,
    *,
    host_id: str,
    evidence_ref: str = "",
) -> list[dict[str, object]]:
    """Convert HTTP ToolResult into normalized http.* facts."""
    if result.status != "ok":
        return []
    status = ""
    server = ""
    for line in (result.output or "").splitlines():
        if line.startswith("status="):
            status = line.split("=", 1)[1].strip()
        elif line.startswith("server="):
            server = line.split("=", 1)[1].strip()
    ref = evidence_ref or f"evidence://preflight/{host_id}/http-001"
    facts: list[dict[str, object]] = []
    if status:
        facts.append(
            {
                "host_id": host_id,
                "fact": "http.response.status",
                "value": status,
                "confidence": 1.0,
                "source": "http_get",
                "evidence_ref": ref,
            }
        )
    if server:
        facts.append(
            {
                "host_id": host_id,
                "fact": "http.response.server_header",
                "value": server,
                "confidence": 0.9,
                "source": "http_get",
                "evidence_ref": ref,
            }
        )
    facts.append(
        {
            "host_id": host_id,
            "fact": "access.http.available",
            "value": True,
            "confidence": 1.0,
            "source": "http_get",
            "evidence_ref": ref,
        }
    )
    return facts

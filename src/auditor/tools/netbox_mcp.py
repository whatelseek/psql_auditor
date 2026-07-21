"""NetBox access via LangChain MCP adapters + netboxlabs/netbox-mcp-server.

Read-only CMDB lookups for intake and IT-audit drift checks.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from contextlib import AsyncExitStack
from typing import Any

from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient

from auditor.config import Settings, get_settings

_DEFAULT_COMMAND = "uv"
_DEFAULT_ARGS = "--directory /opt/netbox-mcp-server run netbox-mcp-server"
_SERVER_NAME = "netbox"

_ENV_PASSTHROUGH = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "UV_CACHE_DIR",
        "XDG_CACHE_HOME",
    }
)

_TRANSPORT_EXC_NAMES = frozenset(
    {
        "ClosedResourceError",
        "ConnectionError",
        "BrokenPipeError",
        "ConnectionResetError",
        "EOFError",
        "TimeoutError",
        "CancelledError",
    }
)


def netbox_mcp_connection(settings: Settings | None = None) -> dict[str, Any]:
    """Build MultiServerMCPClient stdio connection for NetBox MCP."""
    settings = settings or get_settings()
    command = settings.mcp_netbox_command or _DEFAULT_COMMAND
    args = shlex.split(settings.mcp_netbox_args or _DEFAULT_ARGS)
    env: dict[str, str] = {
        k: v
        for k, v in os.environ.items()
        if isinstance(v, str)
        and (k in _ENV_PASSTHROUGH or k.startswith("UV") or k.startswith("XDG"))
    }
    if settings.netbox_url:
        env["NETBOX_URL"] = settings.netbox_url
    if settings.netbox_token:
        env["NETBOX_TOKEN"] = settings.netbox_token
    env["VERIFY_SSL"] = "true" if settings.netbox_verify_ssl else "false"
    env["TRANSPORT"] = "stdio"
    return {
        "transport": "stdio",
        "command": command,
        "args": args,
        "env": env,
    }


def _is_transport_exception(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionError, BrokenPipeError, TimeoutError, EOFError)):
        return True
    if type(exc).__name__ in _TRANSPORT_EXC_NAMES:
        return True
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "broken pipe",
            "connection reset",
            "not connected",
            "connection closed",
            "closed resource",
            "eof",
        )
    )


def _format_mcp_result(result: Any) -> str:
    content = getattr(result, "content", None)
    parts: list[str] = []
    if content is None:
        text = str(result)
    else:
        for item in content:
            text_part = getattr(item, "text", None)
            if text_part is not None:
                parts.append(text_part)
            else:
                try:
                    parts.append(json.dumps(item.model_dump(), default=str))
                except Exception:  # noqa: BLE001
                    parts.append(str(item))
        text = "\n".join(parts) if parts else str(result)
    if getattr(result, "isError", False):
        if text.lower().startswith("netbox error") or text.lower().startswith("mcp error"):
            return text
        return f"NetBox error: {text}" if text else "NetBox error: tool returned isError"
    return text


class NetboxMcpSession:
    """Long-lived LangChain MCP session for netbox-mcp-server."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def _ensure_session(self, settings: Settings) -> Any:
        if self._session is not None:
            return self._session
        if not settings.netbox_url or not settings.netbox_token:
            raise RuntimeError(
                "NETBOX_URL and NETBOX_TOKEN must be set in secrets/connection.md"
            )
        client = MultiServerMCPClient(
            {_SERVER_NAME: netbox_mcp_connection(settings)},
            handle_tool_errors=True,
        )
        stack = AsyncExitStack()
        session = await stack.enter_async_context(
            client.session(_SERVER_NAME, auto_initialize=True)
        )
        self._stack = stack
        self._session = session
        return session

    async def _reset_unlocked(self) -> None:
        if self._stack is not None:
            try:
                await self._stack.aclose()
            except Exception:  # noqa: BLE001
                pass
        self._stack = None
        self._session = None

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        settings: Settings | None = None,
    ) -> str:
        settings = settings or get_settings()
        arguments = arguments or {}
        async with self._lock:
            try:
                session = await self._ensure_session(settings)
                result = await session.call_tool(tool_name, arguments=arguments)
                return _format_mcp_result(result)
            except Exception as exc:  # noqa: BLE001
                if _is_transport_exception(exc):
                    await self._reset_unlocked()
                return f"NetBox error: {type(exc).__name__}: {exc}"

    async def close(self) -> None:
        async with self._lock:
            await self._reset_unlocked()

    async def reconnect(self, settings: Settings | None = None) -> str:
        settings = settings or get_settings()
        async with self._lock:
            await self._reset_unlocked()
            try:
                await self._ensure_session(settings)
                return "NetBox session reconnected successfully"
            except Exception as exc:  # noqa: BLE001
                await self._reset_unlocked()
                return f"NetBox reconnect failed: {type(exc).__name__}: {exc}"


_SESSION = NetboxMcpSession()


async def reconnect_netbox_session() -> str:
    return await _SESSION.reconnect()


def _parse_jsonish(text: str) -> Any:
    raw = (text or "").strip()
    if not raw or raw.lower().startswith("netbox error"):
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re_search_json(raw)
        if match is None:
            return None
        try:
            return json.loads(match)
        except json.JSONDecodeError:
            return None


def re_search_json(text: str) -> str | None:
    import re

    match = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    return match.group(1) if match else None


async def probe_netbox_capabilities(settings: Settings | None = None) -> dict[str, Any]:
    """Connect and sample devices to see which intake fields NetBox can supply."""
    settings = settings or get_settings()
    if not settings.netbox_url or not settings.netbox_token:
        return {
            "reachable": False,
            "error": "NETBOX_URL / NETBOX_TOKEN not configured in secrets/connection.md",
            "fields": {},
            "sample_device": None,
        }

    # Prefer netbox_get_objects naming; fall back to get_objects.
    result = await _SESSION.call_tool(
        "netbox_get_objects",
        {
            "object_type": "devices",
            "filters": {},
            "fields": [
                "id",
                "name",
                "status",
                "device_type",
                "site",
                "location",
                "tenant",
                "role",
                "primary_ip4",
                "primary_ip6",
                "custom_fields",
            ],
        },
        settings=settings,
    )
    if result.lower().startswith("netbox error") and "unknown" in result.lower():
        result = await _SESSION.call_tool(
            "get_objects",
            {
                "object_type": "devices",
                "filters": {},
            },
            settings=settings,
        )

    if result.lower().startswith("netbox error"):
        return {
            "reachable": False,
            "error": result,
            "fields": {},
            "sample_device": None,
        }

    data = _parse_jsonish(result)
    sample: dict[str, Any] | None = None
    if isinstance(data, list) and data:
        sample = data[0] if isinstance(data[0], dict) else None
    elif isinstance(data, dict):
        results = data.get("results") or data.get("objects") or data.get("data")
        if isinstance(results, list) and results and isinstance(results[0], dict):
            sample = results[0]
        elif "name" in data or "id" in data:
            sample = data

    def avail(ok: bool, note: str = "") -> dict[str, Any]:
        return {"available": ok, "note": note}

    fields = {
        "hostname": avail(True, "device.name"),
        "ip": avail(True, "primary_ip4 / primary_ip6"),
        "subnet": avail(True, "via IPAM prefix lookup when IP present"),
        "owner": avail(True, "tenant / role / custom_fields"),
        "location": avail(True, "site / location / rack"),
        "cpu": avail(False, "often absent; custom_fields or inventory items"),
        "ram": avail(False, "often absent; custom_fields or inventory items"),
        "storage": avail(False, "often absent; custom_fields or inventory items"),
        "access_port": avail(False, "custom field / convention"),
        "access_method": avail(False, "custom field / convention (ssh/psql/winrm)"),
    }
    if sample:
        cf = sample.get("custom_fields") or {}
        if isinstance(cf, dict):
            lower_keys = {str(k).lower() for k in cf}
            for key, needles in (
                ("cpu", ("cpu", "cores")),
                ("ram", ("ram", "memory")),
                ("storage", ("disk", "hdd", "ssd", "storage")),
                ("access_port", ("access_port", "port")),
                ("access_method", ("access_method", "access", "protocol")),
            ):
                if lower_keys & set(needles):
                    fields[key] = avail(True, "custom_fields")
        if sample.get("tenant") or sample.get("role"):
            fields["owner"] = avail(True, "tenant / role")
        if sample.get("site") or sample.get("location"):
            fields["location"] = avail(True, "site / location")
        if sample.get("primary_ip4") or sample.get("primary_ip6"):
            fields["ip"] = avail(True, "primary_ip*")

    return {
        "reachable": True,
        "error": "",
        "fields": fields,
        "sample_device": sample,
        "raw_preview": result[:2000],
    }


async def fetch_netbox_device_by_name(
    name: str,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    """Lookup a device by name for drift comparison."""
    settings = settings or get_settings()
    if not name or not settings.netbox_url:
        return None
    result = await _SESSION.call_tool(
        "netbox_get_objects",
        {
            "object_type": "devices",
            "filters": {"name": name},
        },
        settings=settings,
    )
    if result.lower().startswith("netbox error"):
        result = await _SESSION.call_tool(
            "get_objects",
            {"object_type": "devices", "filters": {"name": name}},
            settings=settings,
        )
    data = _parse_jsonish(result)
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    if isinstance(data, dict):
        results = data.get("results") or data.get("objects")
        if isinstance(results, list) and results and isinstance(results[0], dict):
            return results[0]
    return None


@tool
async def netbox_get_objects(
    object_type: str = "devices",
    filters_json: str = "{}",
    fields_json: str = "[]",
) -> str:
    """Query NetBox objects (read-only) via netbox-mcp-server.

    object_type examples: devices, ip_addresses, sites, prefixes.
    filters_json: JSON object of NetBox filters.
    fields_json: optional JSON array of field names to reduce payload size.
    """
    try:
        filters = json.loads(filters_json) if filters_json else {}
        if not isinstance(filters, dict):
            return "NetBox error: filters_json must be a JSON object"
        fields = json.loads(fields_json) if fields_json else []
        if fields and not isinstance(fields, list):
            return "NetBox error: fields_json must be a JSON array"
    except json.JSONDecodeError as exc:
        return f"NetBox error: invalid JSON: {exc}"
    args: dict[str, Any] = {"object_type": object_type, "filters": filters}
    if fields:
        args["fields"] = fields
    result = await _SESSION.call_tool("netbox_get_objects", args)
    if result.lower().startswith("netbox error"):
        return await _SESSION.call_tool("get_objects", args)
    return result


@tool
async def netbox_get_object_by_id(object_type: str, object_id: int) -> str:
    """Get one NetBox object by type and numeric id (read-only)."""
    args = {"object_type": object_type, "object_id": object_id}
    result = await _SESSION.call_tool("netbox_get_object_by_id", args)
    if result.lower().startswith("netbox error"):
        return await _SESSION.call_tool("get_object_by_id", args)
    return result


@tool
async def netbox_get_changelogs(filters_json: str = "{}") -> str:
    """Read NetBox changelog / audit trail entries (read-only)."""
    try:
        filters = json.loads(filters_json) if filters_json else {}
        if not isinstance(filters, dict):
            return "NetBox error: filters_json must be a JSON object"
    except json.JSONDecodeError as exc:
        return f"NetBox error: invalid JSON: {exc}"
    args = {"filters": filters}
    result = await _SESSION.call_tool("netbox_get_changelogs", args)
    if result.lower().startswith("netbox error"):
        return await _SESSION.call_tool("get_changelogs", args)
    return result


def get_netbox_tools() -> list:
    return [netbox_get_objects, netbox_get_object_by_id, netbox_get_changelogs]

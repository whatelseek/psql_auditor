"""Optional MCP client for PostgreSQL MCP servers."""

from __future__ import annotations

import json
import shlex
from typing import Any

from langchain_core.tools import tool

from psql_auditor.config import get_settings


async def _call_mcp(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> str:
    """Invoke a tool on the configured Postgres MCP server.

    Supports:
    - MCP_POSTGRES_URL: SSE/HTTP MCP endpoint
    - MCP_POSTGRES_COMMAND (+ optional MCP_POSTGRES_ARGS): stdio MCP server
    """
    settings = get_settings()
    arguments = arguments or {}

    if not settings.mcp_postgres_url and not settings.mcp_postgres_command:
        return (
            "MCP error: neither MCP_POSTGRES_URL nor MCP_POSTGRES_COMMAND is set. "
            "Fall back to run_sql / SSH tools, or configure an MCP Postgres server."
        )

    try:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
    except ImportError as exc:
        return f"MCP error: mcp package unavailable: {exc}"

    try:
        if settings.mcp_postgres_command:
            args = shlex.split(settings.mcp_postgres_args or "")
            server = StdioServerParameters(
                command=settings.mcp_postgres_command,
                args=args,
            )
            async with stdio_client(server) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool_name, arguments=arguments)
                    return _format_mcp_result(result)

        # HTTP/SSE transport when URL is provided
        try:
            from mcp.client.sse import sse_client
        except ImportError:
            return (
                "MCP error: SSE client not available in this mcp package version. "
                "Use MCP_POSTGRES_COMMAND for stdio instead."
            )

        async with sse_client(settings.mcp_postgres_url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments=arguments)
                return _format_mcp_result(result)
    except Exception as exc:  # noqa: BLE001
        return f"MCP error: {type(exc).__name__}: {exc}"


def _format_mcp_result(result: Any) -> str:
    content = getattr(result, "content", None)
    if content is None:
        return str(result)
    parts: list[str] = []
    for item in content:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
        else:
            try:
                parts.append(json.dumps(item.model_dump(), default=str))
            except Exception:  # noqa: BLE001
                parts.append(str(item))
    return "\n".join(parts) if parts else str(result)


@tool
async def mcp_call_tool(tool_name: str, arguments_json: str = "{}") -> str:
    """Call a tool on the configured PostgreSQL MCP server.

    Args:
        tool_name: MCP tool name (e.g. query, list_tables — depends on the server).
        arguments_json: JSON object string of tool arguments.
    """
    try:
        arguments = json.loads(arguments_json) if arguments_json else {}
        if not isinstance(arguments, dict):
            return "MCP error: arguments_json must be a JSON object"
    except json.JSONDecodeError as exc:
        return f"MCP error: invalid arguments_json: {exc}"
    return await _call_mcp(tool_name, arguments)


@tool
async def mcp_list_tools() -> str:
    """List tools exposed by the configured PostgreSQL MCP server."""
    settings = get_settings()
    if not settings.mcp_postgres_url and not settings.mcp_postgres_command:
        return (
            "MCP error: neither MCP_POSTGRES_URL nor MCP_POSTGRES_COMMAND is set."
        )
    try:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
    except ImportError as exc:
        return f"MCP error: mcp package unavailable: {exc}"

    try:
        if settings.mcp_postgres_command:
            args = shlex.split(settings.mcp_postgres_args or "")
            server = StdioServerParameters(
                command=settings.mcp_postgres_command,
                args=args,
            )
            async with stdio_client(server) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    return _format_tool_list(tools)

        from mcp.client.sse import sse_client

        async with sse_client(settings.mcp_postgres_url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return _format_tool_list(tools)
    except Exception as exc:  # noqa: BLE001
        return f"MCP error: {type(exc).__name__}: {exc}"


def _format_tool_list(tools_result: Any) -> str:
    tools = getattr(tools_result, "tools", tools_result)
    lines = []
    for t in tools:
        name = getattr(t, "name", str(t))
        desc = getattr(t, "description", "") or ""
        lines.append(f"- {name}: {desc}".rstrip())
    return "\n".join(lines) if lines else "No tools reported by MCP server."


def get_mcp_tools() -> list:
    return [mcp_call_tool, mcp_list_tools]

"""Optional MCP client for PostgreSQL MCP servers.

Model Context Protocol (MCP) servers can expose database tools (query, list
schemas, etc.). This module lets the auditor call those tools when configured:

* **stdio** — ``MCP_POSTGRES_COMMAND`` (+ optional ``MCP_POSTGRES_ARGS``)
* **SSE/HTTP** — ``MCP_POSTGRES_URL``

If neither is set, tools return a clear error string and the agent should fall
back to ``run_sql`` / SSH. Failures never raise into the graph; they are
returned as text evidence.
"""

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

    Opens a short-lived MCP session (stdio or SSE), initializes the protocol,
    calls ``tool_name`` with ``arguments``, and formats the content blocks.

    Args:
        tool_name: Name of the remote MCP tool (server-specific).
        arguments: JSON-serializable argument object for the tool.

    Returns:
        Human-readable tool output, or an ``MCP error: …`` string.
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
        # Prefer stdio when a command is configured (common for local MCP servers).
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

        # Otherwise use SSE/HTTP transport against MCP_POSTGRES_URL.
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
    """Flatten MCP ``CallToolResult`` content blocks into plain text.

    Args:
        result: Object returned by ``ClientSession.call_tool``.

    Returns:
        Joined text from content blocks, JSON dumps for structured blocks,
        or ``str(result)`` as a last resort.
    """
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

    Returns:
        MCP tool output text, or an error describing invalid JSON / transport
        problems.
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
    """List tools exposed by the configured PostgreSQL MCP server.

    Useful as a discovery step before ``mcp_call_tool`` when the operator is
    unsure which MCP tools the server provides.

    Returns:
        Bullet list of ``name: description`` lines, or an MCP error string.
    """
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
    """Format ``list_tools`` results as a readable bullet list.

    Args:
        tools_result: MCP list-tools response (object with ``.tools`` or a list).

    Returns:
        Newline-separated ``- name: description`` entries.
    """
    tools = getattr(tools_result, "tools", tools_result)
    lines = []
    for t in tools:
        name = getattr(t, "name", str(t))
        desc = getattr(t, "description", "") or ""
        lines.append(f"- {name}: {desc}".rstrip())
    return "\n".join(lines) if lines else "No tools reported by MCP server."


def get_mcp_tools() -> list:
    """Return LangChain tools for MCP PostgreSQL access.

    Returns:
        ``[mcp_call_tool, mcp_list_tools]`` for binding into the assess model.
    """
    return [mcp_call_tool, mcp_list_tools]

"""PostgreSQL access via LangChain MCP adapters + antonorlov/mcp-postgres-server.

Database evidence for the auditor goes through
[`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters)
``MultiServerMCPClient`` (stdio transport) to the published npm package
`antonorlov/mcp-postgres-server`.

Exposed LangChain tools keep stable names used by playbooks / prompts:

* ``mcp_connect_db`` — optional explicit connect (env ``PG_*`` usually suffices)
* ``mcp_query`` — SELECT only (``SHOW`` rewritten to ``pg_settings``)
* ``mcp_list_schemas`` / ``mcp_list_tables`` / ``mcp_describe_table``
* ``mcp_list_tools`` — discovery via the live MCP session

Mutating remote ``execute`` is intentionally **not** exposed.

A process-wide persistent MCP session is kept (locked) so connection state
survives across parallel REQ workers and cyclic reconnect.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
from contextlib import AsyncExitStack
from typing import Any

from langchain_core.tools import BaseTool, tool
from langchain_mcp_adapters.client import MultiServerMCPClient

from auditor.config import Settings, get_settings

_DEFAULT_COMMAND = "npx"
_DEFAULT_ARGS = "-y mcp-postgres-server"
_SERVER_NAME = "postgres"

# Remote MCP tools we refuse to bind / call.
_BLOCKED_REMOTE_TOOLS = frozenset({"execute"})


def postgres_mcp_connection(settings: Settings | None = None) -> dict[str, Any]:
    """Build a ``MultiServerMCPClient`` stdio connection dict for Postgres MCP."""
    settings = settings or get_settings()
    command = settings.mcp_postgres_command or _DEFAULT_COMMAND
    args = shlex.split(settings.mcp_postgres_args or _DEFAULT_ARGS)
    env = {k: v for k, v in os.environ.items() if isinstance(v, str)}
    env.update(settings.pg_env_for_mcp())
    return {
        "transport": "stdio",
        "command": command,
        "args": args,
        "env": env,
    }


class PostgresMcpSession:
    """Long-lived LangChain MCP session for antonorlov/mcp-postgres-server.

    Uses ``MultiServerMCPClient.session`` under an ``AsyncExitStack`` so the
    stdio subprocess stays up across tool calls until ``reconnect`` / ``close``.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._stack: AsyncExitStack | None = None
        self._client: MultiServerMCPClient | None = None
        self._session: Any = None

    def _build_client(self, settings: Settings) -> MultiServerMCPClient:
        return MultiServerMCPClient(
            {_SERVER_NAME: postgres_mcp_connection(settings)},
            handle_tool_errors=True,
        )

    async def _ensure_session(self, settings: Settings) -> Any:
        """Start LangChain MCP client + session if needed."""
        if self._session is not None:
            return self._session

        client = self._build_client(settings)
        stack = AsyncExitStack()
        session = await stack.enter_async_context(
            client.session(_SERVER_NAME, auto_initialize=True)
        )
        self._client = client
        self._stack = stack
        self._session = session
        return session

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        settings: Settings | None = None,
    ) -> str:
        """Call a remote MCP tool on the persistent LangChain-managed session."""
        settings = settings or get_settings()
        arguments = arguments or {}
        if tool_name in _BLOCKED_REMOTE_TOOLS:
            return (
                "MCP error: mutating execute is disabled for the auditor. "
                "Use mcp_query for SELECT evidence."
            )
        async with self._lock:
            try:
                session = await self._ensure_session(settings)
                result = await session.call_tool(tool_name, arguments=arguments)
                return _format_mcp_result(result)
            except Exception as exc:  # noqa: BLE001
                await self._reset_unlocked()
                return f"MCP error: {type(exc).__name__}: {exc}"

    async def list_tools(self, settings: Settings | None = None) -> str:
        """List tools exposed by the running MCP server."""
        settings = settings or get_settings()
        async with self._lock:
            try:
                session = await self._ensure_session(settings)
                tools = await session.list_tools()
                return _format_tool_list(tools)
            except Exception as exc:  # noqa: BLE001
                await self._reset_unlocked()
                return f"MCP error: {type(exc).__name__}: {exc}"

    async def load_adapted_tools(
        self, settings: Settings | None = None
    ) -> list[BaseTool]:
        """Load LangChain tools from the live MCP session via adapters.

        Filters out blocked remote tools (e.g. ``execute``). Prefer the curated
        ``get_mcp_tools()`` wrappers for playbook-stable names; this helper is
        for diagnostics / future expansion.
        """
        from langchain_mcp_adapters.tools import load_mcp_tools

        settings = settings or get_settings()
        async with self._lock:
            session = await self._ensure_session(settings)
            tools = await load_mcp_tools(
                session,
                server_name=_SERVER_NAME,
                handle_tool_errors=True,
            )
            return [t for t in tools if getattr(t, "name", "") not in _BLOCKED_REMOTE_TOOLS]

    async def _reset_unlocked(self) -> None:
        if self._stack is not None:
            try:
                await self._stack.aclose()
            except Exception:  # noqa: BLE001
                pass
        self._stack = None
        self._session = None
        self._client = None

    async def close(self) -> None:
        """Shut down the MCP subprocess (tests / graceful shutdown)."""
        async with self._lock:
            await self._reset_unlocked()

    async def reconnect(self, settings: Settings | None = None) -> str:
        """Force-close a dead MCP session and open a fresh LangChain MCP session.

        Used by the LangGraph ``reconnect_session`` node when the cyclic audit
        loop detects recoverable MCP/session failures.
        """
        settings = settings or get_settings()
        async with self._lock:
            await self._reset_unlocked()
            try:
                await self._ensure_session(settings)
                return "MCP session reconnected successfully"
            except Exception as exc:  # noqa: BLE001
                await self._reset_unlocked()
                return f"MCP reconnect failed: {type(exc).__name__}: {exc}"


_SESSION = PostgresMcpSession()


def get_mcp_session() -> PostgresMcpSession:
    """Return the process-wide Postgres MCP session singleton."""
    return _SESSION


async def reconnect_mcp_session() -> str:
    """Public helper to recycle the process-wide MCP session."""
    return await _SESSION.reconnect()


def _format_mcp_result(result: Any) -> str:
    """Flatten MCP CallToolResult content blocks into plain text."""
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


def _format_tool_list(tools_result: Any) -> str:
    """Format list_tools results as a bullet list."""
    tools = getattr(tools_result, "tools", tools_result)
    lines = []
    for t in tools:
        name = getattr(t, "name", str(t))
        desc = getattr(t, "description", "") or ""
        lines.append(f"- {name}: {desc}".rstrip())
    return "\n".join(lines) if lines else "No tools reported by MCP server."


_SHOW_ONE = re.compile(
    r"^\s*SHOW\s+([a-zA-Z0-9_.]+)\s*;?\s*$",
    re.IGNORECASE,
)
_SHOW_ALL = re.compile(r"^\s*SHOW\s+ALL\s*;?\s*$", re.IGNORECASE)


def rewrite_show_to_select(sql: str) -> str:
    """Rewrite ``SHOW`` into ``SELECT`` against ``pg_settings``.

    antonorlov/mcp-postgres-server ``query`` accepts SELECT only. Auditors often
    need ``SHOW ssl`` / ``SHOW password_encryption``; this helper translates them.
    """
    text = sql.strip()
    if _SHOW_ALL.match(text):
        return "SELECT name, setting, source FROM pg_settings ORDER BY name"
    match = _SHOW_ONE.match(text)
    if match:
        name = match.group(1).replace("'", "''")
        return (
            "SELECT name, setting, source FROM pg_settings "
            f"WHERE name = '{name}'"
        )
    return sql


# ---------------------------------------------------------------------------
# Curated LangChain tools (stable names for playbooks / prompts)
# ---------------------------------------------------------------------------


@tool
async def mcp_connect_db(
    host: str = "",
    port: int = 5432,
    user: str = "",
    password: str = "",
    database: str = "",
) -> str:
    """Connect the Postgres MCP server to a database (antonorlov/mcp-postgres-server).

    Usually unnecessary when PG_HOST / PG_USER / PG_PASSWORD / PG_DATABASE are
    already set in the environment — the MCP server auto-connects. Use this when
    switching targets mid-audit or recovering from a failed connection.
    """
    settings = get_settings()
    args = {
        "host": host or settings.pg_host or "",
        "port": port or settings.pg_port,
        "user": user or settings.pg_user,
        "password": password or (settings.pg_password or ""),
        "database": database or settings.pg_database,
    }
    missing = [k for k in ("host", "user", "password", "database") if not args[k]]
    if missing:
        return (
            "MCP error: connect_db missing "
            + ", ".join(missing)
            + ". Set PG_* / DATABASE_URL in the environment or pass full credentials."
        )
    return await _SESSION.call_tool("connect_db", args, settings=settings)


@tool
async def mcp_query(sql: str, params_json: str = "[]") -> str:
    """Run a read-only SELECT against PostgreSQL via LangChain MCP adapters.

    Prefer catalog SELECTs, e.g.:
    - SELECT name, setting FROM pg_settings WHERE name = 'ssl'
    - SELECT rolname, rolsuper FROM pg_roles

    SHOW statements are auto-rewritten to pg_settings SELECTs. Mutating SQL is
    not allowed (remote ``execute`` is not exposed).
    """
    try:
        params = json.loads(params_json) if params_json else []
        if not isinstance(params, list):
            return "MCP error: params_json must be a JSON array"
    except json.JSONDecodeError as exc:
        return f"MCP error: invalid params_json: {exc}"

    rewritten = rewrite_show_to_select(sql)
    if not rewritten.lstrip().upper().startswith("SELECT"):
        return (
            "MCP error: only SELECT is allowed via mcp_query. "
            "Use SELECT against pg_settings / pg_roles / pg_extension, etc."
        )
    return await _SESSION.call_tool(
        "query",
        {"sql": rewritten, "params": params},
    )


@tool
async def mcp_list_schemas() -> str:
    """List database schemas via antonorlov/mcp-postgres-server (LangChain MCP)."""
    return await _SESSION.call_tool("list_schemas", {})


@tool
async def mcp_list_tables(schema_name: str = "public") -> str:
    """List tables in a schema via antonorlov/mcp-postgres-server (LangChain MCP)."""
    return await _SESSION.call_tool("list_tables", {"schema": schema_name})


@tool
async def mcp_describe_table(table: str, schema_name: str = "public") -> str:
    """Describe a table's columns via antonorlov/mcp-postgres-server (LangChain MCP)."""
    return await _SESSION.call_tool(
        "describe_table",
        {"table": table, "schema": schema_name},
    )


@tool
async def mcp_list_tools() -> str:
    """List tools exposed by the configured antonorlov/mcp-postgres-server."""
    return await _SESSION.list_tools()


def get_mcp_tools() -> list:
    """Return curated LangChain tools that query Postgres via MCP adapters.

    Playbooks and prompts depend on these stable ``mcp_*`` names.
    """
    return [
        mcp_connect_db,
        mcp_query,
        mcp_list_schemas,
        mcp_list_tables,
        mcp_describe_table,
        mcp_list_tools,
    ]


async def mcp_call_tool(tool_name: str, arguments_json: str = "{}") -> str:
    """Generic MCP tool caller (prefer ``mcp_query`` / ``mcp_*`` helpers)."""
    try:
        arguments = json.loads(arguments_json) if arguments_json else {}
        if not isinstance(arguments, dict):
            return "MCP error: arguments_json must be a JSON object"
    except json.JSONDecodeError as exc:
        return f"MCP error: invalid arguments_json: {exc}"
    if tool_name in _BLOCKED_REMOTE_TOOLS:
        return (
            "MCP error: mutating execute is disabled for the auditor. "
            "Use mcp_query for SELECT evidence."
        )
    if tool_name == "query" and "sql" in arguments:
        arguments = {
            **arguments,
            "sql": rewrite_show_to_select(str(arguments["sql"])),
        }
    return await _SESSION.call_tool(tool_name, arguments)

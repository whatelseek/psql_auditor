"""PostgreSQL access via LangChain MCP adapters + antonorlov/mcp-postgres-server.

Follows the LangChain MCP guide
(https://docs.langchain.com/oss/python/langchain/mcp):

* ``MultiServerMCPClient`` with stdio transport
* **Stateful** ``client.session("postgres")`` so the MCP subprocess (and DB
  connection) survives across tool calls — not the default per-call session
* ``handle_tool_errors=True`` (requires ``langchain-mcp-adapters>=0.3.0``)
* A **pool** of stateful sessions so parallel REQ workers can ``mcp_query``
  concurrently (stdio is single-flight per session)

Production tools are curated ``mcp_*`` wrappers (stable playbook names).
``load_mcp_tools`` is diagnostics-only.

Mutating remote ``execute`` is intentionally **not** exposed.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
from contextlib import AsyncExitStack
from typing import Any

from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient

from auditor.config import Settings, get_settings
from auditor.tools.postgres import is_readonly_sql

_DEFAULT_COMMAND = "npx"
_DEFAULT_ARGS = "-y mcp-postgres-server"
_SERVER_NAME = "postgres"

# Remote MCP tools we refuse to bind / call.
_BLOCKED_REMOTE_TOOLS = frozenset({"execute"})

# Minimal env for the MCP child (avoid copying the whole process environment).
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
        "XDG_CACHE_HOME",
        "npm_config_cache",
        "NPM_CONFIG_CACHE",
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


def postgres_mcp_connection(settings: Settings | None = None) -> dict[str, Any]:
    """Build a ``MultiServerMCPClient`` stdio connection dict for Postgres MCP."""
    settings = settings or get_settings()
    command = settings.mcp_postgres_command or _DEFAULT_COMMAND
    args = shlex.split(settings.mcp_postgres_args or _DEFAULT_ARGS)
    env: dict[str, str] = {
        k: v
        for k, v in os.environ.items()
        if isinstance(v, str)
        and (k in _ENV_PASSTHROUGH or k.startswith("NODE") or k.startswith("NPM"))
    }
    env.update(settings.pg_env_for_mcp())
    return {
        "transport": "stdio",
        "command": command,
        "args": args,
        "env": env,
    }


def _is_transport_exception(exc: BaseException) -> bool:
    """True when the MCP stdio session likely died and should be recycled."""
    if isinstance(exc, (ConnectionError, BrokenPipeError, TimeoutError, EOFError)):
        return True
    name = type(exc).__name__
    if name in _TRANSPORT_EXC_NAMES:
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
                if _is_transport_exception(exc):
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
                if _is_transport_exception(exc):
                    await self._reset_unlocked()
                return f"MCP error: {type(exc).__name__}: {exc}"

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
        """Force-close a dead MCP session and open a fresh LangChain MCP session."""
        settings = settings or get_settings()
        async with self._lock:
            await self._reset_unlocked()
            try:
                await self._ensure_session(settings)
                return "MCP session reconnected successfully"
            except Exception as exc:  # noqa: BLE001
                await self._reset_unlocked()
                return f"MCP reconnect failed: {type(exc).__name__}: {exc}"


class PostgresMcpPool:
    """Pool of ``PostgresMcpSession`` workers for concurrent MCP tool calls.

    Each worker owns its own stdio ``npx mcp-postgres-server`` process. Callers
    acquire a free session, invoke the tool, then release it back to the queue.
    """

    def __init__(self, size: int | None = None) -> None:
        self._configured_size = size
        self._sessions: list[PostgresMcpSession] = []
        self._queue: asyncio.Queue[PostgresMcpSession] | None = None
        self._init_lock = asyncio.Lock()
        self._size = 0

    @property
    def size(self) -> int:
        """Number of pooled sessions (0 until first use)."""
        return self._size

    def _resolve_size(self, settings: Settings) -> int:
        raw = (
            self._configured_size
            if self._configured_size is not None
            else settings.mcp_postgres_pool_size
        )
        try:
            n = int(raw or 1)
        except (TypeError, ValueError):
            n = 1
        return max(1, min(n, 16))

    async def _ensure(self, settings: Settings) -> None:
        if self._queue is not None:
            return
        async with self._init_lock:
            if self._queue is not None:
                return
            size = self._resolve_size(settings)
            sessions = [PostgresMcpSession() for _ in range(size)]
            queue: asyncio.Queue[PostgresMcpSession] = asyncio.Queue()
            for session in sessions:
                queue.put_nowait(session)
            self._sessions = sessions
            self._queue = queue
            self._size = size

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        settings: Settings | None = None,
    ) -> str:
        """Borrow a pooled session, call the remote tool, then release it."""
        settings = settings or get_settings()
        await self._ensure(settings)
        assert self._queue is not None
        session = await self._queue.get()
        try:
            return await session.call_tool(tool_name, arguments, settings=settings)
        finally:
            self._queue.put_nowait(session)

    async def list_tools(self, settings: Settings | None = None) -> str:
        """List tools via one pooled session."""
        settings = settings or get_settings()
        await self._ensure(settings)
        assert self._queue is not None
        session = await self._queue.get()
        try:
            return await session.list_tools(settings=settings)
        finally:
            self._queue.put_nowait(session)

    async def close(self) -> None:
        """Close every pooled MCP subprocess."""
        async with self._init_lock:
            sessions = list(self._sessions)
            self._sessions = []
            self._queue = None
            self._size = 0
        for session in sessions:
            await session.close()

    async def reconnect(self, settings: Settings | None = None) -> str:
        """Reconnect every pooled session (used by the graph reconnect node)."""
        settings = settings or get_settings()
        await self._ensure(settings)
        results = [await session.reconnect(settings) for session in self._sessions]
        failures = [r for r in results if "failed" in r.lower()]
        if failures:
            return (
                f"MCP reconnect failed for {len(failures)}/{len(results)} "
                f"pool workers: {failures[0]}"
            )
        return (
            f"MCP session pool reconnected successfully "
            f"({len(results)} workers)"
        )


_POOL = PostgresMcpPool()


def get_mcp_pool() -> PostgresMcpPool:
    """Return the process-wide Postgres MCP session pool."""
    return _POOL


async def reconnect_mcp_session() -> str:
    """Public helper to recycle every pooled MCP session."""
    return await _POOL.reconnect()


def _format_mcp_result(result: Any) -> str:
    """Flatten MCP CallToolResult; prefix failures with ``MCP error:``."""
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
        if text.lower().startswith("mcp error"):
            return text
        return f"MCP error: {text}" if text else "MCP error: tool returned isError"
    return text


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
    """Rewrite ``SHOW`` into ``SELECT`` against ``pg_settings``."""
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


def _reject_if_not_readonly(sql: str) -> str | None:
    """Return an MCP error string if ``sql`` is not read-only; else ``None``."""
    if is_readonly_sql(sql):
        return None
    return (
        "MCP error: only read-only SQL is allowed via mcp_query "
        "(SELECT / WITH … SELECT / SHOW). Multi-statement or mutating SQL is blocked."
    )


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

    Credentials are never echoed back; evidence logs redact ``password``.
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
    result = await _POOL.call_tool("connect_db", args, settings=settings)
    # Never echo password-bearing args in the tool return path.
    if result.lower().startswith("mcp error"):
        return result
    return (
        f"MCP connect_db ok (host={args['host']}, port={args['port']}, "
        f"user={args['user']}, database={args['database']})"
    )


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
    rejected = _reject_if_not_readonly(rewritten)
    if rejected:
        return rejected
    return await _POOL.call_tool(
        "query",
        {"sql": rewritten, "params": params},
    )


@tool
async def mcp_list_schemas() -> str:
    """List database schemas via antonorlov/mcp-postgres-server (LangChain MCP)."""
    return await _POOL.call_tool("list_schemas", {})


@tool
async def mcp_list_tables(schema_name: str = "public") -> str:
    """List tables in a schema via antonorlov/mcp-postgres-server (LangChain MCP)."""
    return await _POOL.call_tool("list_tables", {"schema": schema_name})


@tool
async def mcp_describe_table(table: str, schema_name: str = "public") -> str:
    """Describe a table's columns via antonorlov/mcp-postgres-server (LangChain MCP)."""
    return await _POOL.call_tool(
        "describe_table",
        {"table": table, "schema": schema_name},
    )


@tool
async def mcp_list_tools() -> str:
    """List tools exposed by the configured antonorlov/mcp-postgres-server."""
    return await _POOL.list_tools()


def get_mcp_tools() -> list:
    """Return curated LangChain tools that query Postgres via MCP adapters."""
    return [
        mcp_connect_db,
        mcp_query,
        mcp_list_schemas,
        mcp_list_tables,
        mcp_describe_table,
        mcp_list_tools,
    ]

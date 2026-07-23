# LangChain / LangGraph MCP (PostgreSQL)

Postgres evidence follows the official LangChain MCP guide:
[Model Context Protocol (MCP)](https://docs.langchain.com/oss/python/langchain/mcp)
via [`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters)
(`>=0.3.0`) and [antonorlov/mcp-postgres-server](https://github.com/antonorlov/mcp-postgres-server).

## Design (aligned with LangChain docs)

Per the docs, `MultiServerMCPClient` is **stateless by default** (fresh session per
`get_tools()` invocation). For a **stateful** stdio server that keeps a DB
connection across calls, use an explicit **stateful session**:

```python
client = MultiServerMCPClient({"postgres": {...}}, handle_tool_errors=True)
async with client.session("postgres") as session:
    ...
```

The auditor does that inside each `PostgresMcpSession` (via `AsyncExitStack`),
then pools several such sessions so parallel REQ workers are not stuck on one
stdio pipe.

```text
AuditorGraph.bind_tools(SSH + mcp_*)
        │
        ▼
curated tools: mcp_query, mcp_connect_db, …
        │
        ▼
PostgresMcpPool  (MCP_POSTGRES_POOL_SIZE workers, default 3)
        │
        ├─ PostgresMcpSession #0 ── MultiServerMCPClient.session("postgres")
        │                              └── npx -y mcp-postgres-server  (PG_*)
        ├─ PostgresMcpSession #1 ── …
        └─ PostgresMcpSession #2 ── …
```

| LangChain concept | Auditor implementation |
|-------------------|-------------------------|
| stdio transport | `postgres_mcp_connection()` → `command`/`args`/`env` |
| Stateful `client.session(name)` | `PostgresMcpSession._ensure_session` |
| `handle_tool_errors=True` (≥0.3.0) | Set on `MultiServerMCPClient` / `load_mcp_tools` |
| `load_mcp_tools(session)` | Not used in production (curated ``mcp_*`` only) |
| Parallel tool use | `PostgresMcpPool` (one stdio process per worker) |

Why not raw `client.get_tools()` for production? Remote tool names are `query`,
`list_tables`, … Playbooks need stable **`mcp_query`**, etc. Curated wrappers also:

- honor ``CallToolResult.isError`` (prefix ``MCP error:``)
- block mutating ``execute``
- rewrite ``SHOW`` → ``SELECT`` on ``pg_settings``
- reject non-read-only SQL (`WITH … SELECT` ok; multi-statement blocked)
- merge `DATABASE_URL` into `PG_*`
- recycle a worker only on transport failure
- reconnect **all** pool workers from graph `reconnect_session`

## Config

```env
MCP_POSTGRES_COMMAND=npx
MCP_POSTGRES_ARGS=-y mcp-postgres-server
MCP_POSTGRES_POOL_SIZE=3
MAX_PARALLEL_ASSESSMENTS=5
MAX_PARALLEL_HOST_JOBS=2
PG_HOST=…
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=…
PG_DATABASE=postgres
# or DATABASE_URL=postgresql://…
```

Tips:

- For faster DB-heavy audits, raise both `MAX_PARALLEL_ASSESSMENTS` (e.g. `10`)
  and `MCP_POSTGRES_POOL_SIZE` toward that value (hard cap `16`).
- Each pool worker is an extra Node/`npx` process — keep the pool modest.

## Reconnect

On recoverable MCP errors the graph calls `reconnect_mcp_session()`, which
reconnects every pooled LangChain MCP session.

## References

- LangChain MCP guide: https://docs.langchain.com/oss/python/langchain/mcp
- Stateful sessions section (same page, `#stateful-sessions`)
- `MultiServerMCPClient` reference: https://reference.langchain.com/python/langchain-mcp-adapters/client/MultiServerMCPClient

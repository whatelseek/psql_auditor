# LangChain MCP (PostgreSQL)

Postgres evidence uses **[langchain-mcp-adapters](https://github.com/langchain-ai/langchain-mcp-adapters)**
`MultiServerMCPClient` (stdio) to spawn [antonorlov/mcp-postgres-server](https://github.com/antonorlov/mcp-postgres-server).

```text
AuditorGraph.bind_tools(SSH + mcp_*)
        │
        ▼
curated tools: mcp_query, mcp_connect_db, …
        │
        ▼
PostgresMcpPool  (MCP_POSTGRES_POOL_SIZE workers, default 3)
        │
        ├─ PostgresMcpSession #0 ── npx mcp-postgres-server
        ├─ PostgresMcpSession #1 ── npx mcp-postgres-server
        └─ PostgresMcpSession #2 ── npx mcp-postgres-server
```

Parallel REQ workers borrow different pool sessions so multiple `mcp_query`
calls can run at once (stdio is still single-flight **per** session).

## Why curated `mcp_*` tools?

Remote MCP tool names are `query`, `list_tables`, … Playbooks and prompts use
stable **`mcp_query`**, **`mcp_list_tables`**, etc. Wrappers also:

- honor ``CallToolResult.isError`` (prefix ``MCP error:``)
- block mutating ``execute``
- rewrite ``SHOW`` → ``SELECT`` on ``pg_settings``
- reject non-read-only SQL (allows ``WITH … SELECT``; blocks multi-statement)
- fill missing ``PG_*`` fields from ``DATABASE_URL`` (including password when host is set)
- recycle a session only on transport failures
- reconnect **all** pool workers on graph ``reconnect_session``

`PostgresMcpPool.load_adapted_tools()` can still load raw adapter tools
(minus ``execute``) for diagnostics.

## Config

```env
MCP_POSTGRES_COMMAND=npx
MCP_POSTGRES_ARGS=-y mcp-postgres-server
MCP_POSTGRES_POOL_SIZE=3
MAX_PARALLEL_ASSESSMENTS=5
PG_HOST=…
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=…
PG_DATABASE=postgres
# or DATABASE_URL=postgresql://…
```

Tips:

- Raise `MCP_POSTGRES_POOL_SIZE` toward `MAX_PARALLEL_ASSESSMENTS` for DB-heavy audits.
- Each worker is an extra Node/`npx` process — keep the pool modest (1–8; hard cap 16).

## Reconnect

On recoverable MCP errors the graph calls `reconnect_mcp_session()`, which
reconnects every pooled LangChain MCP session.

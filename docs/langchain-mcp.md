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
PostgresMcpSession  (process-wide, asyncio.Lock)
        │
        ▼
MultiServerMCPClient.session("postgres")
        │
        ▼
npx -y mcp-postgres-server   (PG_* env)
```

## Why curated `mcp_*` tools?

Remote MCP tool names are `query`, `list_tables`, … Playbooks and prompts use
stable **`mcp_query`**, **`mcp_list_tables`**, etc. Wrappers also:

- block mutating ``execute``
- rewrite ``SHOW`` → ``SELECT`` on ``pg_settings``
- soft-reject non-SELECT SQL
- fill ``connect_db`` blanks from ``PG_*`` / ``DATABASE_URL``
- keep reconnect semantics for the cyclic audit graph

`PostgresMcpSession.load_adapted_tools()` can still load raw adapter tools
(minus ``execute``) for diagnostics.

## Config

```env
MCP_POSTGRES_COMMAND=npx
MCP_POSTGRES_ARGS=-y mcp-postgres-server
PG_HOST=…
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=…
PG_DATABASE=postgres
# or DATABASE_URL=postgresql://…
```

## Reconnect

On recoverable MCP errors the graph calls `reconnect_mcp_session()`, which
closes the LangChain MCP session stack and opens a fresh stdio connection.

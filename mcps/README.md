# MCP registry

Drop-in MCP servers for the auditor. Credentials and IPs stay in inventory /
secrets — never in this folder (except public HTTP endpoints with no auth).

## Layout

| Path | Role |
|------|------|
| `registry.json` | Declares servers (`command` / `args` / `url`, `envFrom`, frameworks) |
| This README | How to add a server |

Runtime setting: `MCPS_DIR` (default `mcps`).

## Current servers

| Server | Transport | Package / URL | Credentials |
|--------|-----------|---------------|-------------|
| `postgres` | stdio | `mcp-postgres-server` | `envFrom: inventory:pg` → `PG_*` |
| `microsoft-learn` | streamable_http | `https://learn.microsoft.com/api/mcp` | none (public) |

Microsoft Learn tools bound for assess: `microsoft_docs_search`,
`microsoft_docs_fetch`, `microsoft_code_sample_search`. The model should call
them when it needs official how-to steps (WinRM, PowerShell, Azure, …) before
inventing commands. Source: [microsoftdocs/mcp](https://github.com/microsoftdocs/mcp).

## Add another server

1. Install / choose an MCP package (stdio) or remote URL (HTTP).
2. Add an entry under `mcpServers` in `registry.json` with `"enabled": true`.
3. For credentialed servers, point `envFrom` at an inventory preset
   (e.g. `inventory:pg`) — do **not** put passwords in `registry.json`.
4. Wire curated LangChain tools (or load dynamically) and bind them in
   `get_mcp_tools()` / `_all_tools()` so the assess LLM can call them.
5. Optionally list framework ids in `frameworks` (empty = available generally).

### Example inventory rows (Postgres)

```markdown
| Access | Host | Port | Username | Password / Token | Extra |
|--------|------|------|----------|------------------|-------|
| SSH | 10.0.0.10 | 22 | ubuntu | … | |
| PostgreSQL | 10.0.0.10 | 5432 | auditor_ro | … | database=postgres |
```

## What the agent does

- Calls curated tools (`mcp_query`, `mcp_connect_db`, …) for Postgres.
- Calls Microsoft Learn tools when it needs official Microsoft execution guidance.
- Uses `mcp_list_servers` to see registered MCPs and credential readiness.
- Must not write secrets into `registry.json`.

## Security

- Commit only launch metadata here (command/args/public URL).
- Keep secrets in `inventory/<client>/` or `secrets/connection.md`.
- Prefer read-only MCP packages; list mutating tool names in `blockedTools`.

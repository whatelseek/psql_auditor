# MCP registry

Drop-in MCP servers for the auditor. **Only PostgreSQL is registered today.**
Credentials and IPs stay in inventory / secrets — never in this folder.

## Layout

| Path | Role |
|------|------|
| `registry.json` | Declares servers (`command`, `args`, `envFrom`, frameworks) |
| This README | How to add a server |

Runtime setting: `MCPS_DIR` (default `mcps`).

## Current servers

| Server | Package | Credentials |
|--------|---------|-------------|
| `postgres` | `mcp-postgres-server` | `envFrom: inventory:pg` → `PG_*` from inventory |

## Add another server (later)

1. Install / choose an MCP package (stdio or HTTP).
2. Add an entry under `mcpServers` in `registry.json` with `"enabled": true`.
3. Point `envFrom` at an inventory preset (e.g. `inventory:pg`) so host/user/password
   are injected at launch — do **not** put passwords in `registry.json`.
4. Add a framework Markdown under `agents/` and list its id in `frameworks`.

### Example inventory rows (Postgres)

```markdown
| Access | Host | Port | Username | Password / Token | Extra |
|--------|------|------|----------|------------------|-------|
| SSH | 10.0.0.10 | 22 | ubuntu | … | |
| PostgreSQL | 10.0.0.10 | 5432 | auditor_ro | … | database=postgres |
```

## What the agent does

- Calls curated tools (`mcp_query`, `mcp_connect_db`, …) for Postgres.
- Uses `mcp_list_servers` to see registered MCPs and credential readiness.
- Must not write secrets into `registry.json`.

## Security

- Commit only launch metadata here (command/args).
- Keep secrets in `inventory/<client>/` or `secrets/connection.md`.
- Prefer read-only MCP packages; list mutating tool names in `blockedTools`.

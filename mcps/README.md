# MCP registry

Drop-in MCP servers for the auditor. The assess agent gets tools from **enabled**
entries; **credentials and IPs stay in inventory / secrets** — never in this folder.

## Layout

| Path | Role |
|------|------|
| `registry.json` | Declares servers (`command`, `args`, `envFrom`, frameworks) |
| This README | How to add a server |

Runtime setting: `MCPS_DIR` (default `mcps`).

## Add a server

1. Install / choose an MCP package (stdio or HTTP).
2. Add or edit an entry under `mcpServers` in `registry.json`.
3. Set `"enabled": true`.
4. Point `envFrom` at an inventory preset (`inventory:pg` / `inventory:mysql` /
   `inventory:oracle`) so host/user/password are injected at launch.
5. Add a framework Markdown under `agents/` with matching `detect` rules and list
   its id in `frameworks`.
6. Put Access rows in the client inventory (see below) — do **not** put passwords
   in `registry.json`.

### Example inventory rows

```markdown
| Access | Host | Port | Username | Password / Token | Extra |
|--------|------|------|----------|------------------|-------|
| SSH | 10.0.0.10 | 22 | ubuntu | … | |
| PostgreSQL | 10.0.0.10 | 5432 | auditor_ro | … | database=postgres |
| MySQL | 10.0.0.11 | 3306 | auditor_ro | … | database=app |
| Oracle | 10.0.0.12 | 1521 | auditor_ro | … | service=ORCL |
```

## What the agent does

- Calls curated tools (`mcp_query`, …) for Postgres, or future server tools once enabled.
- Uses `mcp_list_servers` to see which MCPs are registered and whether credentials look ready.
- Uses `mcp_connect_db` to point Postgres at a target; passwords still come from settings/inventory overlays — the agent should not write secrets into `registry.json`.

## Security

- Commit only launch metadata here (command/args/templates).
- Keep secrets in `inventory/<client>/` or `secrets/connection.md`.
- Prefer read-only MCP packages; list mutating tool names in `blockedTools`.

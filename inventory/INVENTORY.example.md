# Inventory (example)

Copy to `inventory/<ClientName>/INVENTORY.md` (folder name ≈ client name).
Put **credentials in the table below** (not in `docker-compose.yml`). The agent
loads that table after you answer the client name during intake.

## Credentials & access

| Access | Host / URL | Port | Username | Password / Token | Database |
|--------|------------|------|----------|------------------|----------|
| SSH | 10.0.0.10 | 22 | auditor | | |
| PostgreSQL | 10.0.0.10 | 5432 | postgres | changeme | postgres |

`Database` is used for PostgreSQL rows. Optional private-key path: put
`SSH_PRIVATE_KEY_PATH=…` in a short ``env`` fence under this table, or in
`connection.md`. Lab host keys: set `SSH_STRICT_HOST_KEY=false` in `.env` /
Compose (default for this stack).

Postgres MCP is declared in `mcps/registry.json`. Passwords stay in this
inventory table — never in the MCP registry.

Optional dedicated file: `inventory/<ClientName>/connection.md` (same table or
legacy ``env`` block).

## Client

- Name: Example Corp
- Engagement: Lab PostgreSQL / Ubuntu CIS

## In-scope hosts

| Hostname | IP | Role | Access | Notes |
|----------|-----|------|--------|-------|
| db-01.example.com | 10.0.0.10 | PostgreSQL 16 | SSH, psql | Primary audit target |
| app-01.example.com | 10.0.0.20 | App | SSH | Optional |

## Out of scope

- Production replicas not listed above
- Windows / WinRM (unless OpenSSH is enabled)

# Inventory (example)

Copy to `inventory/<ClientName>/INVENTORY.md` (folder name ≈ client name).
Put **credentials in the table below** (not in `docker-compose.yml`). The agent
loads that table after you answer the client name during intake.

## Credentials & access

| Access | Host / URL | Port | Username | Password / Token | Database |
|--------|------------|------|----------|------------------|----------|
| SSH | 10.0.0.10 | 22 | auditor | | |
| PostgreSQL | 10.0.0.10 | 5432 | postgres | changeme | postgres |
| WinRM | 10.0.0.20 | 5985 | Administrator | changeme | transport=ntlm |

`Database` is used for PostgreSQL rows. WinRM Extra may set `transport=ntlm`
(or `basic` / `credssp`), `use_ssl=true` (port **5986** implies HTTPS). Optional
private-key path for SSH: put `SSH_PRIVATE_KEY_PATH=…` in a short ``env`` fence
under this table, or in `connection.md`. Lab host keys: set
`SSH_STRICT_HOST_KEY=false` in `.env` / Compose (default for this stack).

Postgres MCP is declared in `mcps/registry.json`. Passwords stay in this
inventory table — never in the MCP registry.

Optional dedicated file: `inventory/<ClientName>/connection.md` (same table or
legacy ``env`` block).

Optional **audit plan**: `inventory/<ClientName>/PLAN.md` — Markdown table of
Host / IP → frameworks for the intake scope step (see
[`PLAN.example.md`](PLAN.example.md)). Overrides auto-detected frameworks when
present; you still confirm before the audit starts.

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
- WinRM targets without a `WinRM` Access row (use OpenSSH `SSH` row instead)

# inventory/

Per-client audit scope **and credentials**.

| Path | Purpose |
|------|---------|
| [`INVENTORY.example.md`](INVENTORY.example.md) | Template (safe to commit) |
| `<ClientName>/INVENTORY.md` | Scope + credentials table (host, port, user, secret) |
| `<ClientName>/connection.md` | Optional credentials-only file (same table) |

During intake, after you give the **client name**, the agent:

1. Resolves `inventory/<ClientName>/` (case-insensitive)
2. Loads SSH / Postgres from the **Credentials & access** table
3. Checks whether `INVENTORY.md` exists for scope

Do **not** put client passwords in `docker-compose.yml`. Global
`secrets/connection.md` is optional fallback only; **inventory wins**.

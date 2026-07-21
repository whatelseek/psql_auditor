# secrets/

Optional **global** fallback credentials. Prefer per-client credentials in
[`inventory/<ClientName>/INVENTORY.md`](../inventory/INVENTORY.example.md).

| File | Purpose |
|------|---------|
| [`connection.example.md`](connection.example.md) | Template (safe to commit) |
| `connection.md` | Optional global defaults (gitignored) |

When intake loads a client inventory, those keys **override** this file.

```bash
# Preferred: put creds in inventory
# inventory/TestCompany/INVENTORY.md  → ## Credentials & access (table)

# Optional global fallback:
cp secrets/connection.example.md secrets/connection.md
```

Do **not** put `SSH_*`, `PG_*`, `DATABASE_URL`, `NETBOX_*`, or `MCP_*` in `docker-compose.yml`.

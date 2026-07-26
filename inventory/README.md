# inventory/

Per-client audit scope **and credentials** for inventory-driven audit launch.

| Path | Purpose |
|------|---------|
| [`INVENTORY.example.md`](INVENTORY.example.md) | Template (safe to commit) |
| [`PLAN.example.md`](PLAN.example.md) | Optional host→framework plan override |
| `<ClientName>/INVENTORY.md` | Primary Markdown inventory (hosts + credentials) |
| `<ClientName>/INVENTORY.yaml` / `.json` | Structured inventory (also supported) |
| `<ClientName>/CREDENTIALS.md` | Optional credentials-only file |
| `<ClientName>/QUESTIONNAIRE.md` | Optional combined questionnaire |
| `<ClientName>/questionnaires/*.md` | Optional technology-specific questionnaires |
| `<ClientName>/NETWORK.md` / `EXCEPTIONS.md` | Optional network / exception notes |

Client names must contain only Latin letters, digits, and underscores
(example: `Testcompany`). Spaces and other special characters are rejected.

## CLI

```bash
psql-auditor inventory validate Testcompany
psql-auditor inventory analyze Testcompany
psql-auditor audit plan Testcompany
psql-auditor audit start Testcompany --confirm
```

See [`docs/inventory-driven-audit.md`](../docs/inventory-driven-audit.md).

During chat intake, after you give the **client name**, the agent:

1. Resolves `inventory/<ClientName>/` (case-insensitive)
2. Loads SSH / Postgres / WinRM from the credentials table
3. Checks whether `INVENTORY.md` (or YAML/JSON) exists for scope
4. Proposes frameworks and **waits for confirmation** before execution

Do **not** put client passwords in `docker-compose.yml`. Prefer secret
references (`vault://…`). Global `secrets/connection.md` is optional fallback
only; **inventory wins**.

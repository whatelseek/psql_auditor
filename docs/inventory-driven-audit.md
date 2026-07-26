# Inventory-driven infrastructure audit launch

This document describes the inventory → validate → optional discovery →
reconcile → plan → confirm → execute workflow (INPUT-003 / INPUT-005).

Related checklist items: `INPUT-001` (open — acceptance candidate
[`5286a4d`](https://github.com/whatelseek/psql_auditor/commit/5286a4d773f62d0bc796b205ddd18994bdfc89af)),
`INPUT-003` (partial), `INPUT-005` (partial), `CORE-006` (partial until
independent acceptance).

## Operator flow

```text
Create inventory/<ClientName>/
  ├─ INVENTORY.md | .yaml | .json
  ├─ CREDENTIALS.md          (optional dedicated credentials table)
  └─ QUESTIONNAIRE.md / questionnaires/ / EXCEPTIONS.md / NETWORK.md
        │
        ▼
psql-auditor inventory validate <ClientName>
psql-auditor inventory analyze <ClientName>
        │  optional read-only discovery when OS/services missing
        │  reconcile discovered facts (never overwrite inventory facts)
        ▼
psql-auditor audit plan <ClientName>
        │  shows detected assets + selected frameworks
        │  does NOT start execution
        ▼
psql-auditor audit start <ClientName> --confirm
        │  rejects plan_stale if inventory changed
        │  builds AuditRequest (with inventory version/hash)
        ▼
arun_request → audit_run_id
```

Client names must match `^[A-Za-z0-9_]+$` (Latin letters, digits, underscore).
Example directory: `inventory/Testcompany/`.

## Supported inventory formats

| Format | File names |
|--------|------------|
| Markdown | `INVENTORY.md` |
| YAML | `INVENTORY.yaml` / `INVENTORY.yml` |
| JSON | `INVENTORY.json` |

Credentials may live in the inventory file **or** in `CREDENTIALS.md` /
`connection.md`. Columns:

`Access | Host / URL | Port | Username | Password / Token | Database`

Plaintext secrets are never stored in `ClientInventory`, `AuditPlan`,
`AuditRequest`, logs, or API responses — only `secret_ref` / `has_secret`.

## Pre-assessment (live discovery)

Hosts may declare only host ID, IP/DNS, connection type, port, and credential
reference. Missing OS/services yield `needs_discovery` (information), not a
blocking error.

Before final framework selection, analyze may apply a read-only discovery
collector (SSH/Linux or WinRM/Windows) that gathers OS, hostname, services,
listening ports, and PostgreSQL process/package signals.

Discovered facts use `source=discovered` and do **not** overwrite inventory
facts. Conflicts are recorded and surface as clarification items; conflicting
OS evidence does not select an OS framework until clarified.

Weak evidence (port-only PostgreSQL) does **not** select `postgres_cis`.

## Confirmation gate and stale plans

`audit start` without `--confirm` fails with `plan_not_confirmed`.

On `--confirm` / API approve:

1. Reload current inventory
2. Compare `inventory_version_id` + `content_hash` with the stored plan
3. Reject with `plan_stale` when inventory changed (regenerate the plan)

Confirmed plans map to an INPUT-001 `AuditRequest` that embeds the expected
inventory `version_id` and `content_hash`, then execute via `arun_request`.

At the execution boundary, `validate_audit_request_semantics()` reloads the
current inventory through the loader/normalizer and rejects with
`inventory_hash_mismatch` / `inventory_version_mismatch` when the pinned
identity diverges (CLI start, HTTP start, direct `arun_request`, and replay of
saved `audit_request.json`). Identity is the normalized
`ClientInventory.version`, not raw file bytes.

## API

| Method | Path | Notes |
|--------|------|--------|
| POST | `/clients/{client_id}/inventory` | Validate |
| POST | `/clients/{client_id}/inventory/analyze` | Analyze + draft plan |
| POST | `/clients/{client_id}/audit-plans` | Same as analyze |
| POST | `/audit-plans/{plan_id}/confirm` | Stale-checked; `start=true` awaits `astart_confirmed_audit` (no `asyncio.run`) |

## Module map

| Concern | Module |
|---------|--------|
| Domain inventory | `src/auditor/domain/inventory.py` |
| Domain audit plan | `src/auditor/domain/audit_plan.py` |
| Loaders / normalize / detect / select / plan | `src/auditor/inventory/` |
| Discovery + reconcile | `src/auditor/inventory/discovery.py` |
| CLI | `src/auditor/cli.py` (`psql-auditor`) |
| HTTP | `src/auditor/api/inventory_routes.py` |
| Tests | `tests/test_inventory_driven_audit.py` |

## Open limitations (not accepted as done)

- Production live SSH/WinRM discovery collector is injectable; default analyze
  uses a no-op collector unless a discoverer is supplied (tests inject
  `StaticDiscoveryCollector`). Wiring automatic SSH/WinRM tool calls into
  analyze remains an operational follow-up.
- Clarifications, exceptions, historical comparison, and report regeneration
  remain under later checklist items / `CORE-006` / `E2E-001`.
- `INPUT-001` and `CORE-006` stay open/partial until independent acceptance.
- Execution still requires a Markdown `INVENTORY.md` path for semantic
  AuditRequest validation even when YAML/JSON was used for planning.

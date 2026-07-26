# Inventory-driven infrastructure audit launch

This document describes the inventory → analyze → plan → confirm →
`AuditRequest` workflow introduced for INPUT-003 / INPUT-005 (and consumed by
the INPUT-001 acceptance candidate).

Related checklist items: `INPUT-001` (open — acceptance candidate
[`5286a4d`](https://github.com/whatelseek/psql_auditor/commit/5286a4d773f62d0bc796b205ddd18994bdfc89af)),
`INPUT-003`, `INPUT-005`, `CORE-006` (still open / partial until independent
acceptance).

## Operator flow

```text
Create inventory/<ClientName>/
  └─ INVENTORY.md | .yaml | .json   (+ optional QUESTIONNAIRE.md, CREDENTIALS.md, …)
        │
        ▼
psql-auditor inventory validate <ClientName>
psql-auditor inventory analyze <ClientName>
psql-auditor audit plan <ClientName>
        │
        │  system shows detected assets + selected frameworks
        │  (does NOT start execution)
        ▼
psql-auditor audit start <ClientName> --confirm
        │
        ▼
AuditRequest JSON (secret-free) under
inventory/<ClientName>/.audit_plans/audit_request.json
```

Client names must match `^[A-Za-z0-9_]+$` (Latin letters, digits, underscore).
Example directory: `inventory/Testcompany/`.

## Supported inventory formats

| Format | File names |
|--------|------------|
| Markdown | `INVENTORY.md` |
| YAML | `INVENTORY.yaml` / `INVENTORY.yml` |
| JSON | `INVENTORY.json` |

CSV/Excel are out of scope for this slice.

Markdown must include an in-scope hosts table (Host / OS / Services / IP) and
may include a credentials table. Credential **plaintext is never stored** in the
normalized model — only `secret_ref` / `has_secret`.

## What analyze produces

1. Normalized `ClientInventory` with provenance-bearing facts
2. Inventory version id + content hash (reproducible audits)
3. Technology detections (`confirmed` / `possible` / …)
4. Framework selection decisions (`selected` / `rejected` with reasons)
5. Draft `AuditPlan` that **requires explicit confirmation**

Example (Testcompany fixture):

- 5 hosts (4 Linux/Ubuntu, 1 Windows Server)
- 2 PostgreSQL instances
- Selected: Ubuntu CIS, Windows Server, PostgreSQL CIS, host_facts (general infra)
- 8 audit target instances (hosts are not duplicated)

## Confirmation gate

`audit start` without `--confirm` fails with `plan_not_confirmed`.
`--reject` marks the plan rejected. Only a confirmed plan can be converted into
an INPUT-001 `AuditRequest` payload.

## API

| Method | Path |
|--------|------|
| POST | `/clients/{client_id}/inventory` |
| POST | `/clients/{client_id}/inventory/analyze` |
| POST | `/clients/{client_id}/audit-plans` |
| POST | `/audit-plans/{plan_id}/confirm` |

## Module map

| Concern | Module |
|---------|--------|
| Domain inventory | `src/auditor/domain/inventory.py` |
| Domain audit plan | `src/auditor/domain/audit_plan.py` |
| Loaders / normalize / detect / select / plan | `src/auditor/inventory/` |
| CLI | `src/auditor/cli.py` (`psql-auditor`) |
| HTTP | `src/auditor/api/inventory_routes.py` |
| Tests | `tests/test_inventory_driven_audit.py` |

## Open limitations (not accepted as done)

- Full execution lifecycle after `AuditRequest` (clarifications, exceptions,
  historical comparison, report regeneration) remains under later checklist
  items / `CORE-006` / `E2E-001`.
- `INPUT-001` and `CORE-006` stay open until independent acceptance review.
- Questionnaire answer mapping and live discovery enrichment are scaffolded via
  side-file discovery only.
- Windows Server checklist is a minimal operational scaffold (`agents/windows_server.md`).

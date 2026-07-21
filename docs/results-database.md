# Results PostgreSQL warehouse

Filled checklist cells (status / observation / recommendation) can be dual-written
to a **results warehouse** database, separate from the PostgreSQL instance under
audit (`PG_*` / `DATABASE_URL` / MCP).

Evidence files (tool stdout, `finding.json`, reports) stay on disk under
`artifacts/<client>/…`. The warehouse is the **session tracker**: each new audit
gets a monotonic **session number** per client, and every stored check is tagged
with that number.

## Sessions

| Event | Warehouse action |
|-------|------------------|
| New audit (after intake) | `INSERT` next `session_number` (`#1`, `#2`, …) with status `running` |
| Chat disconnect / cancel | status → `interrupted` (+ pending REQ ids, continue thread) |
| Finalize / update report | host results + requirement cells written; status → `completed` |
| Continue | resumes the **same** session (does not allocate a new number) |

Ask in Open WebUI:

```text
Which sessions need continue?
List audit sessions
Какие сессии прерваны?
continue session 3 for Acme
```

## Layout

With `RESULTS_DB_PER_CLIENT=true` (default), each client gets its own database:

```text
results_<client_slug>
  audit_sessions            -- session_number UNIQUE per client
  hosts
  host_results              -- session_id + session_number on every row
  framework_requirements    -- checklist snapshot for the session/framework
  requirement_results       -- filled cells (also carry session_number)
```

## Config

```env
# Off by default — enable when a warehouse Postgres is available
RESULTS_DB_ENABLED=true
# Admin DSN used to CREATE DATABASE (per-client) and write results.
# Do NOT reuse the audit-target DATABASE_URL / PG_* credentials here.
RESULTS_DATABASE_URL=postgresql://results_admin:secret@results-db:5432/postgres
RESULTS_DB_PER_CLIENT=true
RESULTS_DB_NAME_PREFIX=results_
```

Set `RESULTS_DB_PER_CLIENT=false` to write into the database named in
`RESULTS_DATABASE_URL` instead of creating `results_<slug>` databases.

## When data is written

| Hook | Source value | Trigger |
|------|--------------|---------|
| Intake complete | (session start) | New audit allocates `session_number` |
| Finalize | `finalize` | End of a checklist audit (per host/framework) |
| Update report | `update_report` | Post-audit `Update the report` / `Обнови отчёт` |

Writes are best-effort: warehouse errors are logged and do not fail the audit.

Disk `meta.json` also stores `results_session_number` so continue/finalize can
re-attach to the correct session after restart.

## What is stored

- Session number (monotonic per client), status, continue thread, pending REQs
- Host key (`evidence_host_id` / SSH host segment)
- Aggregate pass/fail/partial/error/skipped + compliance %
- Full requirement list (title, category, severity, how_to_verify, pass_criteria)
- Per-REQ status, observation, recommendation, notes — **all with session_number**

**Not stored:** SSH/MCP tool output, passwords, private keys, raw evidence files.

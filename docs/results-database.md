# Results PostgreSQL warehouse

Filled checklist cells (status / observation / recommendation) can be dual-written
to a **results warehouse** database, separate from the PostgreSQL instance under
audit (`PG_*` / `DATABASE_URL` / MCP).

Evidence files (tool stdout, `finding.json`, reports) stay on disk under
`artifacts/<client>/…`. The warehouse stores structured checklist snapshots and
timestamped host results for historical comparison.

## Layout

With `RESULTS_DB_PER_CLIENT=true` (default), each client gets its own database:

```text
results_<client_slug>
  hosts
  audit_runs
  host_results              -- one row per host×framework write (timestamped)
  framework_requirements    -- checklist snapshot for the run/framework
  requirement_results       -- filled cells (no tool stdout / secrets)
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
| Finalize | `finalize` | End of a checklist audit (per host/framework) |
| Update report | `update_report` | Post-audit `Update the report` / `Обнови отчёт` |

Writes are best-effort: warehouse errors are logged and do not fail the audit.

## What is stored

- Host key (`evidence_host_id` / SSH host segment)
- Run id, client name/slug, framework id
- Aggregate pass/fail/partial/error/skipped + compliance %
- Full requirement list (title, category, severity, how_to_verify, pass_criteria)
- Per-REQ status, observation, recommendation, notes

**Not stored:** SSH/MCP tool output, passwords, private keys, raw evidence files.

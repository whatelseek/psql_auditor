# Results PostgreSQL warehouse

Filled checklist cells (status / observation / recommendation) can be dual-written
to a **results warehouse** database, separate from the PostgreSQL instance under
audit (`PG_*` / `DATABASE_URL` / MCP).

Evidence files (tool stdout, `finding.json`, reports) stay on disk under
`artifacts/<client>/…`. The warehouse is the **session tracker**: each new audit
gets a monotonic **session number** per client, and every stored check is tagged
with that number.

## Sessions vs LangGraph checkpoints

| Concept | Where | What it is |
|---------|--------|------------|
| **Audit session** (`#1`, `#2`, …) | Results Postgres (`RESULTS_DB_*`) | Operator-facing run id per client; used to list interrupted audits across many clients |
| **LangGraph checkpoint** | Sqlite under `CHECKPOINT_PATH` | Internal graph state so **continue** can resume mid-assess / HITL after disconnect |

You list and pick sessions in chat via the warehouse. You resume work with
**continue** (which loads the checkpoint for that session’s thread). Asking
about a “checkpoint” in free text is **not** a separate query — use session
phrases below, then **continue**.

## Chat phrases (Open WebUI)

Intent matching is **phrase-based** (EN/RU patterns), not full free-form LLM
routing. Prefer the examples below. Full routing table:
[`chat-intent.md`](chat-intent.md) (`list_sessions` intent).

Slash shortcuts (Workspace → Prompts) are installed by
`python3 openwebui/install_owui_prompts.py` — e.g. `/list-sessions`,
`/continue-session`, `/update-report`. Full list:
[`owui-slash-commands.md`](owui-slash-commands.md). Use model **auditor**
(except `/dashboard` → **Visualizer**).

### List sessions / which need continue

Works when the message clearly mentions sessions (or “need continue”):

```text
Which sessions need continue?
List audit sessions
Show me sessions
Show me audit sessions for Acme
Interrupted sessions
Какие сессии прерваны?
Список сессий
Сессии для продолжения
Нужно продолжить
```

Optional client filter: add `for <Client>` / `для <Client>` (also used when
continuing a numbered session).

The reply is a markdown table (session #, client, status, framework, pending
REQs, continue thread) plus copy-paste `[AUDIT_CONTINUE:…]` markers for
interrupted rows.

Requires `RESULTS_DB_ENABLED=true`. If the warehouse is off, the agent explains
how to enable it.

### List results (REQ cells for a session)

Show filled warehouse cells for one client session (host summary + REQ table):

```text
List results for AlphaCo session 2
list-results AlphaCo 2
/list-results
```

Slash `/list-results` prompts for `client` and session `#`. Without a session
number, the newest warehouse session for that client is used. Cells appear
**as each REQ is assessed** (live dual-write), and again after finalize /
**Update the report**.

### List status (host progress for a session)

```text
List status for AlphaCo session 2
list-status AlphaCo 2
/list-status
```

Table columns: Hostname, IP, Framework, Status (`15/60 ready` = filled cells /
checklist size).

### List host (assessment by hostname + framework)

```text
list-host 10.200.29.79 it_audit
list-host pg-db it_audit for AlphaCo
/list-host
```

Shows the newest matching host/framework REQ table (optionally scoped with
`for <Client>`).

### Resume (same session — does not allocate a new number)

```text
continue
resume
продолжи
далее
continue session 3 for Acme
продолжи сессию 3 для Acme
```

Or paste the marker from an interrupt / list-sessions reply:

```text
[AUDIT_CONTINUE:<thread_id>]
```

Resolution order for bare **continue**:

1. Explicit `continue session N for Client` (warehouse)
2. Newest **interrupted** warehouse session among known client folders
3. Newest interrupted run on disk (`artifacts/*/meta.json` with `status=interrupted`)

### What does **not** work today

These fall through to a **new audit** (or other intents) because they are not
matched as session-list / continue:

```text
What's the latest checkpoint?
Show last checkpoint for Acme
Where did we leave off?
Статус чекпоинта
```

Use **List audit sessions** / **Which sessions need continue?** instead, then
**continue** (or `continue session N for Client`).

## Session lifecycle

| Event | Warehouse action |
|-------|------------------|
| New audit (after intake) | `INSERT` next `session_number` (`#1`, `#2`, …) with status `running` |
| Chat disconnect / cancel | status → `interrupted` (+ pending REQ ids, continue thread) |
| Each filled REQ (assess) | live upsert of that cell + host aggregates (session stays `running`) |
| Finalize / update report | refresh host results + cells; status → `completed` |
| Continue | resumes the **same** session (does not allocate a new number) |

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

Learned **playbook memory** (preferred SSH/SQL recipes) is stored once on the
**shared** database from `RESULTS_DATABASE_URL`:

```text
playbook_memory             -- framework_id + entry_key (REQ-* / _framework)
```

See [`long-term-memory.md`](long-term-memory.md).

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
| Assess (per REQ) | `live` | Each filled checklist cell during `assess_parallel` |
| Refill finding | `refill` | Post-audit refill of observation/recommendation |
| Finalize | `finalize` | End of a checklist audit (per host/framework) |
| Update report | `update_report` | Post-audit `Update the report` / `Обнови отчёт` |
| Successful tool (learn) | `playbook_memory` | Learned SSH/SQL recipes (shared DB) |

Writes are best-effort: warehouse errors are logged and do not fail the audit.
Each `(session, host, framework)` has a single `host_results` row; cells
upsert on `(host_result_id, req_id)`.

Disk `meta.json` also stores `results_session_number` so continue/finalize can
re-attach to the correct session after restart.

## What is stored

- Session number (monotonic per client), status, continue thread, pending REQs
- Host key (`evidence_host_id` / SSH host segment)
- Aggregate pass/fail/partial/error/skipped + compliance %
- Full requirement list (title, category, severity, how_to_verify, pass_criteria)
- Per-REQ status, observation, recommendation, notes — **all with session_number**
- Learned playbook recipes (`playbook_memory` on the shared DB)

**Not stored:** SSH/MCP tool output, passwords, private keys, raw evidence files.

## Related

- Intent routing (`list_sessions`): [`chat-intent.md`](chat-intent.md)
- Pre-audit intake (session start): [`pre-audit-intake.md`](pre-audit-intake.md)
- Starting audits: [`starting-an-audit.md`](starting-an-audit.md)
- Docs index: [`README.md`](README.md)

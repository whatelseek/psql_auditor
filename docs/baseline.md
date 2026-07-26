# CORE-000 — Reproducible baseline, verification commands, project map

This document is the **authoritative baseline** for comparing subsequent
changes. Numbers below were measured on a clean virtualenv using
`constraints.txt`; they are not copied from older notes.

## Revisions

| Role | SHA |
|------|-----|
| Historical reviewed revision (task seed) | `67b7b083da7df0892dd232cb164e781b3ac11099` |
| Baseline measurement revision (this doc) | `f513134d03b764bd9ca33da44d346cc3a550051c` (+ CORE-000 commit on top) |

Update the “measurement revision” row when regenerating lock/results.

## Python and reproducible install

| Item | Value |
|------|-------|
| Python used for measurement | **3.12.3** (host). CI pins **3.12**. |
| Known seed note | Task text cited 3.12.13; this environment provides 3.12.3. |
| Lock mechanism | `constraints.txt` (pip-compile, extras=`dev`) |

### Clean-checkout installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]' -c constraints.txt
```

Regenerate the lock after dependency changes:

```bash
make lock
# or: python -m piptools compile --extra=dev --strip-extras -o constraints.txt pyproject.toml
```

## Canonical verification commands

| Gate | Command | Notes |
|------|---------|-------|
| Unit tests | `make test-unit` | `pytest -m unit` (default marker via `tests/conftest.py`) |
| Integration tests | `make test-integration` | `pytest -m integration`; **0 collected** today (see below) |
| Full suite | `make test` | Entire `tests/` tree |
| Formatter check | `make format-check` | `ruff format --check src tests` |
| Linter | `make lint` | `ruff check src tests` |
| Type checker | `make typecheck` | `mypy -p auditor` |
| Combined gates | `make check` | format + lint + typecheck + full suite |
| Baseline compare | `make baseline-compare` | full suite vs `docs/baseline-failures.txt` |

### Unit vs integration selection

There is **no** reliable live-service integration suite today: warehouse, MCP,
SSH, and WinRM tests use mocks/tmp paths. Introducing fake separation would be
dishonest.

Therefore:

* markers `unit` / `integration` are registered in `pyproject.toml`;
* `tests/conftest.py` auto-marks unmarked tests as `unit`;
* `make test-integration` is expected to collect **zero** tests (exit code 5
  treated as success) until real live-service tests are added and marked
  `@pytest.mark.integration`.

## Actual command results (clean venv, locked install)

Measured after:

```text
python3 -m venv /tmp/core000-verify
. /tmp/core000-verify/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]' -c constraints.txt
```

| Command | Result (unedited summary) |
|---------|---------------------------|
| dependency installation | **OK** — editable `auditor==0.1.0` + pinned deps from `constraints.txt` |
| `make test-unit` | **6 failed, 250 passed, 1 warning** |
| `make test-integration` | **256 deselected** (0 collected; treated as OK) |
| `make test` | **6 failed, 250 passed, 1 warning** |
| `make format-check` | **FAIL** — `71 files would be reformatted, 34 files already formatted` |
| `make lint` | **FAIL** — `Found 199 errors` (F401×135, I001×26, E501×19, F821×7, …) |
| `make typecheck` | **FAIL** — `Found 82 errors in 17 files (checked 64 source files)` |
| `make check` | **FAIL** (stops on first red gate; all gates above are red except install) |
| CORE-001/002/003 focused | **27 passed** (`test_client_audit_run_identity`, `test_audit_run_job`, `test_canonical_result_identity`) |

Historical seed (task text, not re-measured here): at `67b7b08` — 196 passed / 8 failed.
Current full suite under locked deps: **250 passed / 6 failed** (report-export failures cleared once `python-docx` / `openpyxl` are installed via the lock).

## Failing / skipped / xfail inventory

No `xfail` or intentional `skip` markers are used to hide baseline defects.

| Node ID | Status | Root cause (short) | Baseline? | Related defect |
|---------|--------|--------------------|-----------|----------------|
| `tests/test_anonymization.py::test_regex_anonymization_ipv4_ipv6_email_reversible` | failed | Second email left as `admin@example.com` after first becomes `EMAIL_001` (token collision / incomplete second match) | yes | BASE-ANON-001 |
| `tests/test_frameworks.py::test_route_framework_by_alias` | failed | Alias `"IT audit"` routes to `postgres_cis` instead of expected `it_audit` | yes | BASE-FW-001 |
| `tests/test_frameworks.py::test_catalog_lists_drop_ins` | failed | Catalog text no longer contains `it_audit` (agent renamed/removed) | yes | BASE-FW-002 |
| `tests/test_frameworks.py::test_select_frameworks_for_ubuntu_postgres_host` | failed | IT-domain selection returns `host_facts` not `it_audit` | yes | BASE-FW-003 |
| `tests/test_frameworks.py::test_select_frameworks_it_domain_only` | failed | Expects `['it_audit']`, gets `host_facts` / `host_facts_ru` | yes | BASE-FW-004 |
| `tests/test_hitl.py::test_hitl_skip_then_finalize` | failed | Final chat report is management summary; word `skipped` not present | yes | BASE-HITL-001 |

Skipped: none intentional. Integration collection: all tests deselected by marker.

### Quality-gate baseline (not pytest)

| Gate | Summary | Baseline defect |
|------|---------|-----------------|
| ruff format | 71 files would be reformatted | BASE-FMT-001 |
| ruff lint | 199 errors (mostly unused imports / import order) | BASE-LINT-001 |
| mypy | 82 errors in 17 files (Protocol vs façade attrs, unused ignores, …) | BASE-MYPY-001 |

These are **not** disabled. CI runs them with `continue-on-error` and records outcomes; `make baseline-compare` is the hard gate for **new test regressions**.

## Production entry-point map

Traced from `src/auditor/api/openai_compat.py` → `AuditorGraph` → workflows.
Test helpers are omitted.

| Operation | User/API entry point | Production module | Main callable | Required IDs | Storage touched |
|-----------|----------------------|-------------------|---------------|--------------|-----------------|
| Start new audit | OWUI chat / `POST /v1/chat/completions` or `/v1/responses` → intent `audit` | `api/openai_compat.py` → `graph.py` → `workflows/multi_runner.py` | `_run_or_resume_once` → `AuditorGraph.arun` → `multi_runner.arun` | Creates `client_id`, `audit_run_id`; jobs get `job_id` | client registry, audit registry, evidence dirs, checkpoints, optional `audit_sessions` |
| Intake questionnaire | Same path when intake enabled | `workflows/intake.py` | `intake_gate` | Allocates/reuses `client_id`, creates `audit_run_id` | evidence rebind `<slug>/<audit_run_id>`, intake progress, audit registry |
| Single-framework run | Internal / tests; also used by multi scheduler | `workflows/runner.py` | `arun_one` | `client_id`, `audit_run_id` (created if missing) | evidence, audit/asset registries, checkpoints |
| Resume HITL / intake | Chat reply with `[AUDIT_HITL:…]` / `[AUDIT_INTAKE:…]` | `api/openai_compat.py` → `runner.py` | `aresume` | Existing LangGraph `thread_id`; preserves `audit_run_id` | checkpoints, evidence |
| Continue interrupted | `continue` / `continue session N for Client` / `[AUDIT_CONTINUE:…]` | `results_store.resolve_continue_target` → `runner.acontinue` | `acontinue` | Explicit session **or** `audit_run_id` / evidence key (no latest-run) | checkpoints, evidence, audit registry, warehouse session |
| Follow-up revise REQ | intent `revise_req` | `followup.py` | `run_revise_req` | Explicit `audit_run_id` / evidence path in text/history | evidence findings, optional warehouse |
| Follow-up refill | intent `refill_finding` | `followup.py` | `run_refill_finding` | Same as revise | evidence + warehouse cells |
| Update report | intent `update_report` | `followup.py` | `run_update_report` | Explicit run id | evidence reports, warehouse aggregates |
| Anonymize report | intent `anonymize_report` | `followup.py` | `run_anonymize_report` | Explicit run id | new `<run>_anon` evidence tree |
| Ad-hoc commands | intent `adhoc` | `adhoc.py` | `run_adhoc_commands` | Explicit prior run **or** new `audit_run_id` | evidence (nested adhoc run) |
| List sessions/status/results | intents `list_*` | `results_store.py` via `graph.alist_*` | warehouse queries | client name; session # preferred | PostgreSQL results DB |
| Report generation (MD/DOCX/XLSX) | End of assess / update-report | `workflows/finalize.py`, `report_exports.py` | `finalize`, `write_report_exports` | Run evidence root (`audit_run_id` in meta) | `report.md` / `.docx` / `.xlsx` under evidence |
| Archive creation | Finalize (when `archive_enabled`) | `report_archive.py` | `package_and_publish_archive` | evidence `run_id` | ZIP under evidence / publish URL |
| Archive download | `GET /v1/downloads/{filename}?token=…` | `api/openai_compat.py` | `download_archive` | archive filename ↔ evidence run | ZIP on disk |

### ID requirements by flow

| Flow | `client_id` | `audit_run_id` | `job_id` | `result_id` |
|------|-------------|----------------|----------|-------------|
| New audit | required (created) | required (created) | per framework job | per finding (CORE-003) |
| Resume / continue | preserved | preserved (explicit) | existing jobs | n/a |
| Follow-up / report regen | from meta | **required explicit** | n/a | reused/created on write |
| Warehouse write | required on finding | **required** | n/a | required for upsert |
| Download archive | n/a | via evidence/archive name | n/a | n/a |

## Storage and migration map

| Store | Technology/path | Owner module | Data scope | Identity fields | Schema/migration | Source of truth |
|-------|-----------------|--------------|------------|-----------------|------------------|-----------------|
| AuditRun / AuditJob registry | SQLite `artifacts/.audit_registry.sqlite` | `audit_registry.py` | business runs + job attempts | `audit_run_id`, `job_id`, `client_id` | `migrations/001_*.sql` (applied by `_ensure_schema`) | **canonical** for run/job lifecycle |
| Client registry | SQLite `artifacts/.client_registry.sqlite` | `client_registry.py` | durable clients | `client_id`, `slug` | `migrations/003_*.sql` (DDL mirror) | **canonical** for client identity |
| Asset registry | SQLite `artifacts/.asset_registry.sqlite` | `asset_registry.py` | hosts/assets per client | `asset_id`, `client_id` | created in module | **canonical** for asset_id |
| Evidence files / manifests | `artifacts/<client_slug>/<audit_run_id>/…` | `evidence_store.py` | tool stdout, finding.json, meta.json | `audit_run_id`, `client_id` in meta/findings | layout convention CORE-001 | **canonical** for raw evidence |
| LangGraph checkpoints | Sqlite `artifacts/.checkpoints/auditor.sqlite` (settings) | `workflows/runner.ensure_async_checkpointer` | graph state / interrupts | `thread_id` | LangGraph schema | **canonical** for resume state |
| Results warehouse | PostgreSQL `RESULTS_DATABASE_URL` (± per-client DB) | `results_store.py` | sessions, host_results, requirement_results | `audit_run_id`, `client_id`, `result_id`, session_number | `002` + `003` ALTERs via `_ensure_schema` | **canonical** for warehouse aggregates; sessions **secondary** |
| `audit_sessions` | table in warehouse | `results_store.py` | UI session numbers / continue phrases | `session_number`, `audit_run_id` | schema + CORE-001 columns | **compatibility / secondary** to AuditRun |
| Multi-session JSON | under evidence run | `session_store.py` | multi-host thread map | thread_id, evidence run | JSON files | **derived** / runtime aid |
| Generated reports | `report.md` / `.docx` / `.xlsx` in evidence | `finalize.py`, `report_exports.py` | operator reports | inherit run meta | n/a | **derived** from findings |
| Archives | `*_audit.zip` (+ `archive.json`) | `report_archive.py` | downloadable packages | evidence run id in name | n/a | **derived** |
| Playbook memory | warehouse `playbook_memory` / files | `memory/playbook_store.py` | learned recipes | framework/req | module schema | **canonical** for playbooks |
| Legacy flat evidence | `artifacts/<ClientName>/` | `legacy_compat.py` | pre-CORE-001 layouts | often missing `audit_run_id` | adapter only | **legacy** — report, do not guess |
| Temp evidence ids | `YYYYMMDDTHHMMSSZ_<hex>` before rebind | `evidence_store.new_run_id` | pre-intake folder | temporary | n/a | **temporary** |

### Migrations (execution order)

| Order | File | Applied how |
|-------|------|-------------|
| 1 | `migrations/001_audit_run_job.sql` | Auto via `AuditRegistry._ensure_schema` on first registry open |
| 2 | `migrations/002_canonical_result_identity.sql` | Auto via `ResultsStore._ensure_schema` (ALTER + unique indexes) |
| 3 | `migrations/003_client_audit_run_separation.sql` | Clients DDL via `ClientRegistry`; warehouse columns via `ResultsStore._ensure_schema` |

Production does **not** run a separate migrate CLI today; opening the registry/warehouse applies DDL. SQL files are the documented mirror for ops.

## Defect → module map

| Defect ID | Current module(s) | Implementation status | Notes |
|-----------|-------------------|-----------------------|-------|
| CORE-000 | `docs/baseline.md`, `Makefile`, `constraints.txt`, `.github/workflows/ci.yml` | implemented (this task) | Baseline process |
| CORE-001 | `client_registry.py`, `legacy_compat.py`, `evidence_store.py`, `workflows/intake.py`, `workflows/runner.py`, `workflows/multi_runner.py`, `results_store.py`, `run_resolve.py` | implemented | client_id ≠ audit_run_id |
| CORE-002 | `domain/audit_models.py`, `audit_registry.py`, `workflows/multi_runner.py`, `workflows/runner.py` | implemented | AuditRun vs AuditJob |
| CORE-003 | `domain/result_identity.py`, `result_identity_bind.py`, `evidence_store.py`, `results_store.py` | implemented | canonical result identity |
| BASE-ANON-001 | `anonymization.py` | present / failing test | email double-replace bug |
| BASE-FW-001…004 | `frameworks.py`, `agents/*.md` | present / tests stale vs catalog | `it_audit` expectations vs `host_facts` |
| BASE-HITL-001 | `workflows/finalize.py`, `hitl.py` | present / failing assert | summary omits “skipped” |
| BASE-FMT-001 | whole tree | tooling red | ruff format not yet applied project-wide |
| BASE-LINT-001 | whole tree | tooling red | 199 ruff issues |
| BASE-MYPY-001 | `workflows/protocols.py` + façade modules | tooling red | Protocol incomplete vs runtime |

## CI

Workflow: `.github/workflows/ci.yml`

1. Python 3.12  
2. `pip install -e '.[dev]' -c constraints.txt`  
3. format / lint / typecheck (logged; `continue-on-error` while baseline-red)  
4. unit + integration + full suite  
5. `make baseline-compare` (**hard fail** on new test regressions)  
6. CORE-001/002/003 focused suites must pass  

## Remaining limitations

* Host Python is 3.12.3; CI uses 3.12.x — pin exact patch in CI only if required later.  
* No live integration tests yet; marker infrastructure is ready.  
* Quality gates (format/lint/mypy) are intentionally red and visible, not silenced.  
* `make check` is not green end-to-end until quality debt is paid.  
* Warehouse migrations are apply-on-connect, not a standalone migrator.  
* Master product checklist beyond CORE-000…003 / BASE-* was not found in-repo; extend the defect table when new IDs are introduced.

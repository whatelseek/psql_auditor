# `psql_auditor` — Master Development and Acceptance Checklist

Checklist version: **1.7**  
Date: **2026-07-26**  
Repository: `whatelseek/psql_auditor`  
Baseline commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)  
Latest reviewed revision: [`00cb8ba`](https://github.com/whatelseek/psql_auditor/commit/00cb8ba)  
Total tasks: **71**

## Status summary

| Status | Count |
| --- | ---: |
| Complete `[x]` | **6 / 71 (8.5%)** |
| Partially complete `[~]` | **5 / 71 (7.0%)** |
| Open `[ ]` | **60 / 71 (84.5%)** |
| Not fully complete | **65 / 71 (91.5%)** |

Completed: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`.

Partially complete: `CORE-006`, `INPUT-005`, `FLOW-007`, `OPS-004`, `DOC-001`.

## Latest verification

`AUD-003` adds the shared canonical fixture package on top of the AUD-002
gates. Local development and GitHub Actions use the same Make targets. All
mandatory gates are green.

| Check | Verified result |
| --- | --- |
| Format | 115 files already formatted |
| Lint | Passed |
| Type check | Passed, 67 files |
| Unit tests | 313 passed |
| PostgreSQL integration tests | 7 passed |
| Full suite | 320 passed |
| Defect map | `validate-defect-map: OK` (71/71) |
| Clean CI | pending CORE-001 push |

Controlled negative runs:

- [Run 30194952566](https://github.com/whatelseek/psql_auditor/actions/runs/30194952566):
  a deliberately broken unit test made the pipeline red.
- [Run 30195039647](https://github.com/whatelseek/psql_auditor/actions/runs/30195039647):
  deliberate lint and type errors made both gates fail.

## Quality assessment

| Area | Baseline | Current | Change |
| --- | ---: | ---: | ---: |
| Architecture and separation of concerns | 4.0/10 | 6.7/10 | +2.7 |
| Execution/result identity | 3.5/10 | 7.0/10 | +3.5 |
| Testability and regression coverage | 5.5/10 | 8.0/10 | +2.5 |
| Maintainability | 3.5/10 | 6.8/10 | +3.3 |
| Production readiness | 3.5/10 | 6.5/10 | +3.0 |
| **Overall code rating** | **4.0/10** | **7.1/10** | **+3.1** |

## Task register

### M0 — Baseline, tests, and CI

- [x] `AUD-001` — Record the current reproducible baseline.
- [x] `AUD-002` — Establish unified local and CI quality gates.
- [x] `AUD-003` — Prepare shared deterministic test fixtures.

`AUD-001` is complete: the defect-to-module map covers all 71 checklist IDs
with `make validate-defect-map` enforced in CI.

`AUD-003` closure evidence:

- shared module `tests/fixtures/canonical_audit.py` with
  `build_canonical_scenario()` → immutable `CanonicalScenario`;
- fixed UTC clock `FIXED_NOW = 2026-07-26T09:00:00Z` via `FixedClock`;
- two clients, alpha with previous+current runs, beta with one run;
- two frameworks each defining distinct `REQ-001`, two linux assets;
- all seven result statuses plus observation/formula/history/exception cases;
- deterministic fake LLM scenarios reused through `DeterministicFakeChatModel`;
- validation in `tests/test_canonical_fixtures.py`; sample reuse in identity,
  quality-gate LLM, and report-export tests.

`AUD-002` closure evidence:

- canonical targets: `format-check`, `lint`, `typecheck`, `test-unit`,
  `test-integration`, `test`, and `check`;
- CI invokes the same Make targets without `continue-on-error`;
- `scripts/run_pytest_group.py` rejects zero-test discovery;
- each PostgreSQL test creates, migrates, and drops an `aud002_<hex>` database;
- `DeterministicFakeChatModel` is injected through a model factory;
- external HTTP/LLM access is blocked in mandatory tests;
- controlled red runs and the final green run are linked above.

### M1 — Identifiers and domain model

- [x] `CORE-001` — Separate `client_id` from `audit_run_id`.

`CORE-001` closure evidence:

- `require_client_id` / `require_audit_run_id` reject empty and swapped ids;
- warehouse `start_session` / upsert paths require both identifiers;
- `AuditRegistry.save_run` rejects client reassignment;
- resume/bootstrap reject conflicting client ownership;
- legacy API `run_id` means evidence folder, not `audit_run_id`;
- tests reuse AUD-003 fixtures in `tests/test_client_audit_run_identity.py`.

- [x] `CORE-002` — Separate `AuditRun` from `AuditJob`.
- [x] `CORE-003` — Introduce canonical result identity.
- [ ] `CORE-004` — Introduce structured `AssessmentResult`.
- [ ] `CORE-005` — Isolate checkpoints and artifacts by audit run.
- [~] `CORE-006` — Remove hidden global mutable state.

### M2 — Inputs and audit planning

- [ ] `INPUT-001` — Introduce a strict `AuditRequest`.
- [ ] `INPUT-002` — Enforce strict framework validation.
- [ ] `INPUT-003` — Introduce a validated inventory model.
- [ ] `INPUT-004` — Introduce a tool registry and capability policy.
- [~] `INPUT-005` — Implement deterministic preflight and `AuditPlan`.

### M3 — LangGraph orchestration and evidence collection

- [ ] `FLOW-001` — Make graph state typed and minimal.
- [ ] `FLOW-002` — Replace internal `asyncio.gather` with LangGraph `Send`.
- [ ] `FLOW-003` — Implement a lossless result reducer.
- [ ] `FLOW-004` — Extract a dedicated requirement worker/subgraph.
- [ ] `FLOW-005` — Add timeouts, retries, and backpressure.
- [ ] `FLOW-006` — Implement correct resume and cancellation.
- [~] `FLOW-007` — Remove the process-wide graph singleton.
- [ ] `EVID-001` — Normalize tool output.
- [ ] `EVID-002` — Enforce read-only behavior and safe invocation.
- [ ] `EVID-003` — Preserve provenance for every evidence item.
- [ ] `EVID-004` — Replace fragile JSON parsing with structured output.
- [ ] `EVID-005` — Introduce evidence sufficiency and confidence.
- [ ] `EVID-006` — Protect immutable framework fields.
- [ ] `EVID-007` — Prevent hidden data loss during truncation.

### M4 — PostgreSQL, history, and exceptions

- [ ] `DB-001` — Add versioned database migrations.
- [ ] `DB-002` — Introduce repository and transaction boundaries.
- [ ] `DB-003` — Separate initial, external, analyst, and effective assessments.
- [ ] `DB-004` — Add optimistic concurrency and an audit log.
- [ ] `HIST-001` — Retrieve the previous comparable result.
- [ ] `HIST-002` — Implement a deterministic change classifier.
- [ ] `EXC-001` — Introduce an approved-exception registry.
- [ ] `EXC-002` — Apply exceptions to structured observed items.
- [ ] `HIST-003` — Feed history and exceptions into the current assessment.
- [ ] `HIST-004` — Add repeat-audit end-to-end regression tests.

### M5 — Unified report generation

- [ ] `REPORT-001` — Create a dedicated reporting package.
- [ ] `REPORT-002` — Implement a versioned `ReportDataset`.
- [ ] `REPORT-003` — Build the dataset from structured sources.
- [ ] `REPORT-004` — Implement cross-record validation.
- [ ] `REPORT-005` — Implement a single metrics engine.
- [ ] `REPORT-006` — Create canonical `report.json` and checksum.
- [ ] `REPORT-007` — Generate Markdown from `ReportDataset`.
- [ ] `REPORT-008` — Implement management-ready Excel output.
- [ ] `REPORT-009` — Implement management-ready Word output.
- [ ] `REPORT-010` — Implement atomic publication and versioning.
- [ ] `REPORT-011` — Integrate the reporting service into all call sites.
- [ ] `REPORT-012` — Complete the reporting regression suite.

### M6 — Anonymization and external model review

- [ ] `REVIEW-001` — Define a versioned `ReviewPackage`.
- [ ] `REVIEW-002` — Implement a reversible anonymization map.
- [ ] `REVIEW-003` — Add leak detection before sending.
- [ ] `REVIEW-004` — Implement the external-model adapter.
- [ ] `REVIEW-005` — Validate the external-model response.
- [ ] `REVIEW-006` — Implement atomic de-anonymization.
- [ ] `REVIEW-007` — Persist external review and recompute effective results.
- [ ] `REVIEW-008` — Define failure and publication semantics.
- [ ] `REVIEW-009` — Test the complete external-review path.

### M7 — Analyst corrections and regeneration

- [ ] `ANALYST-001` — Implement deterministic import of reviewed Excel.
- [ ] `ANALYST-002` — Store overrides transactionally and version reports.
- [ ] `ANALYST-003` — Add explicit service, CLI, and API operations.
- [ ] `ANALYST-004` — Add import/regeneration round-trip tests.

### M8 — Observability, cleanup, and release gate

- [ ] `OPS-001` — Introduce a typed error taxonomy.
- [ ] `OPS-002` — Add structured logs, metrics, and a run manifest.
- [ ] `OPS-003` — Remove legacy Markdown parsing from production flow.
- [~] `OPS-004` — Complete modular cleanup and dependency review.
- [~] `DOC-001` — Update user and developer documentation.
- [ ] `DOC-002` — Create a fully synthetic sample package.
- [ ] `CI-001` — Complete the full release pipeline.
- [ ] `E2E-001` — Pass the final acceptance scenario.

## Current blockers

- `CORE-006`: remove process-wide mutable graph/settings singletons.
- `DOC-001`: synchronize `docs/baseline.md` with the accepted `AUD-002`/`CORE-001`
  state and update stale evidence-layout examples to
  `artifacts/<client_slug>/<audit_run_id>/`.
- `CI-001` remains open even though current quality gates are green: its release
  acceptance also requires workflow/report/review E2E and migration coverage.

## Status rules

- `[ ]` Open: no acceptance review has confirmed the task.
- `[~]` Partial: meaningful implementation exists, but at least one acceptance
  criterion or proof is missing.
- `[x]` Complete: every acceptance criterion has code/test evidence and the
  required verification has passed.

The Russian checklist is the detailed canonical version. This English version
is its synchronized status and task register for implementation planning and
handoff.
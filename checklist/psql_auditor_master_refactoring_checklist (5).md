# `psql_auditor` — Master Development and Acceptance Checklist

Checklist version: **1.14**  
Date: **2026-07-26**  
Repository: `whatelseek/psql_auditor`  
Baseline commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)  
Latest independently reviewed revision: [`83434eb`](https://github.com/whatelseek/psql_auditor/commit/83434eb94643bfeb0df196b0f7f5b35b25415af8)  
Total tasks: **77**

## Status summary

| Status | Count |
| --- | ---: |
| Complete `[x]` | **10 / 77 (13.0%)** |
| Partially complete `[~]` | **5 / 77 (6.5%)** |
| Open `[ ]` | **62 / 77 (80.5%)** |
| Not fully complete | **67 / 77 (87.0%)** |

Completed: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`, `CORE-004`, `CORE-005`, `INPUT-001`, `INPUT-003`.

Partially complete: `CORE-006`, `INPUT-005`, `FLOW-007`, `OPS-004`, `DOC-001`.

## Latest verification

PR #36 (inventory-driven audit + SSH/WinRM discovery) is merged. Independent
review of the inventory-driven launch path accepted `INPUT-001` and
`INPUT-003` at
[`83434eb`](https://github.com/whatelseek/psql_auditor/commit/83434eb94643bfeb0df196b0f7f5b35b25415af8).
`INPUT-005` remains `[~]`. `INPUT-002` remains `[ ]` (Markdown framework
registry candidate on PR #37). Tool adapters `TOOL-001`…`TOOL-005` are open
backlog items. Checklist acceptance statuses are not changed automatically by
green CI.

| Check | Verified result |
| --- | --- |
| Format | Passed |
| Lint | Passed |
| Type check | Passed, 89 files |
| Unit tests | 460 passed |
| Integration tests | 8 passed |
| Full suite | 468 passed |
| Defect map | `validate-defect-map: OK` (77/77) |
| Prior clean CI (PR #36 merge base) | See Actions after PR #36 merge |
| Prior clean CI (PR #35 review base) | [Run 30209929260](https://github.com/whatelseek/psql_auditor/actions/runs/30209929260), all jobs passed |

### Closed findings carried from PR #35 (superseded by PR #36)

- stale `AuditPlan` confirmation after inventory modification;
- `CREDENTIALS.md` was detected but not loaded;
- `audit start` created a request without starting execution;
- API start called `asyncio.run()` inside an active event loop;
- saved `AuditRequest` could be replayed after inventory modification.

## Quality assessment

| Area | Baseline | Current | Change |
| --- | ---: | ---: | ---: |
| Architecture and separation of concerns | 4.0/10 | 7.7/10 | +3.7 |
| Execution/result identity | 3.5/10 | 8.2/10 | +4.7 |
| Testability and regression coverage | 5.5/10 | 8.5/10 | +3.0 |
| Maintainability | 3.5/10 | 7.2/10 | +3.7 |
| Production readiness | 3.5/10 | 6.3/10 | +2.8 |
| **Overall code rating** | **4.0/10** | **7.4/10** | **+3.4** |

## Task register

### M0 — Baseline, tests, and CI

- [x] `AUD-001` — Record the current reproducible baseline.
- [x] `AUD-002` — Establish unified local and CI quality gates.
- [x] `AUD-003` — Prepare shared deterministic test fixtures.

Closure evidence:

- defect-to-module map covers all 77 checklist IDs and is enforced in CI;
- canonical local and CI targets include format, lint, typecheck, unit, integration and full-suite tests;
- deterministic shared fixtures and fake LLM scenarios are reused across regression tests;
- mandatory tests block unintended external HTTP/LLM access.

### M1 — Identifiers and domain model

- [x] `CORE-001` — Separate `client_id` from `audit_run_id`.
- [x] `CORE-002` — Separate `AuditRun` from `AuditJob`.
- [x] `CORE-003` — Introduce canonical result identity.
- [x] `CORE-004` — Introduce structured `AssessmentResult`.
- [x] `CORE-005` — Isolate checkpoints and artifacts by audit run.
- [~] `CORE-006` — Remove hidden global mutable state.

`CORE-006` remains partial. `ApplicationRuntime` ownership and multiple lifecycle
race fixes are implemented, but complete removal of legacy process-wide mutable
state still requires a dedicated independent acceptance review.

### M2 — Inputs and audit planning

- [x] `INPUT-001` — Introduce a strict `AuditRequest`.

Acceptance evidence:

- strict, typed and immutable versioned request model;
- mandatory client, inventory, targets, framework versions, tool profile and run settings;
- secret-shaped request fields are forbidden;
- inventory reference pins normalized `version_id` and `content_hash`;
- semantic validation reloads the current inventory through the loader/normalizer;
- stale requests fail with `inventory_hash_mismatch` or `inventory_version_mismatch`;
- the same execution-boundary validation applies to CLI, HTTP, direct
  `AuditorGraph.arun_request()` and saved-request replay;
- rejection occurs before jobs, sessions or external calls;
- regression tests verify secret-safe errors and persisted request handling.

- [ ] `INPUT-002` — Enforce strict framework validation.

Partial evidence (acceptance still open):

- Markdown `FrameworkRegistry` for `agents/*.md` with optional YAML frontmatter;
- without frontmatter: id from filename, title from H1, deterministic
  `src-<hash>` version;
- multiline requirement sections and Markdown lists;
- compact catalog + compact requirement index + full text for the current
  requirement only;
- invalid frameworks remain visible with errors but are not executable;
- drop-in `.md` frameworks require no Python changes;
- tests: `tests/test_framework_registry.py`, `tests/test_checklist.py`.

- [ ] `AGENT-001` — Provide administrator-managed Markdown audit agents under `agents/`.
- [x] `INPUT-003` — Introduce a validated inventory model.

Acceptance evidence:

- canonical `ClientInventory`, `InventoryHost`, `InventoryService`,
  `InventoryFact` and `CredentialReference` models;
- Markdown, YAML and JSON loading with error/warning/information validation levels;
- stable normalized inventory `version_id` and `content_hash`;
- separate `CREDENTIALS.md` parsing, merge, duplicate handling and host mapping;
- plaintext secrets are excluded from inventory, plan, request, API response and
  persisted secret-free artifacts;
- missing OS becomes `needs_discovery`, not a blocking validation error;
- Testcompany fixtures cover five hosts, multiple formats, credentials and version changes.

The incomplete YAML/JSON execution path does not block `INPUT-003`; it belongs to
execution integration rather than the validated inventory domain model.

- [ ] `INPUT-004` — Introduce a tool registry and capability policy.
- [ ] `TOOL-001` — SSH execution adapter.
- [ ] `TOOL-002` — WinRM PowerShell adapter.
- [ ] `TOOL-003` — HTTP/HTTPS request adapter.
- [ ] `TOOL-004` — TCP connectivity adapter.
- [ ] `TOOL-005` — SNMP adapter.
- [~] `INPUT-005` — Implement deterministic preflight and `AuditPlan`.

Partial evidence:

- typed `AuditPlan` with mandatory explicit confirmation;
- deterministic technology detection and framework selection with select/reject reasons;
- stale-plan rejection on confirm/start when inventory **or** discovery/effective
  facts hashes diverge;
- secret-safe `CREDENTIALS.md` / `credentials.md` / `connection.md` runtime
  credential resolution (secrets never persisted in models, plans, API, logs, or
  evidence);
- production `SshDiscoveryCollector` / `WinrmDiscoveryCollector` /
  `CompositeDiscoveryCollector` on the default analyze path
  (`--no-discovery` / `{ "discovery": false }` keep the no-op path);
- read-only SSH/WinRM command sets; PostgreSQL confirmed only with strong
  evidence (port 5432 alone does not select `postgres_cis`);
- typed discovery errors, per-host timeout/retry, one-host failure isolation;
- sanitized discovery evidence under `artifacts/<slug>/preflight/…` with
  deterministic preflight revisions;
- CLI sync `start_confirmed_audit` / API `await astart_confirmed_audit` create a
  validated `AuditRequest`, invoke `arun_request` and return `audit_run_id`
  (confirmed start does not silently re-run discovery; `--refresh-discovery`
  optional);
- docs: `docs/inventory-driven-audit.md`; tests:
  `tests/test_input005_discovery.py`,
  `tests/integration/test_ssh_discovery_container.py`.

Remaining work:

- YAML/JSON inventory execution integration beyond the validated domain model;
- independent acceptance review for production discovery (do not mark `[x]`
  automatically);
- dedicated tool adapters tracked under `TOOL-001`…`TOOL-005`.

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

- `INPUT-005`: complete YAML/JSON execution integration and independent
  acceptance of production discovery.
- `TOOL-001`…`TOOL-005`: dedicated SSH / WinRM / HTTP / TCP / SNMP adapters.
- `AGENT-001` / `INPUT-002`: administrator-managed agent authoring with strict
  framework validation.
- `FLOW-007`: remove deprecated process-wide graph getters after independent review.
- `DOC-001`: synchronize baseline and evidence-layout documentation.
- `CI-001`: complete workflow/report/review E2E and migration coverage.

## Status rules

- `[ ]` Open: no acceptance review has confirmed the task.
- `[~]` Partial: meaningful implementation exists, but at least one acceptance criterion or proof is missing.
- `[x]` Complete: every acceptance criterion has code/test evidence and required verification has passed.

The Russian checklist is the synchronized translated status register. Both files
must be updated together.

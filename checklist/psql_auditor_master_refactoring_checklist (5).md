# `psql_auditor` — Master Development and Acceptance Checklist

Checklist version: **1.14**  
Date: **2026-07-27**  
Repository: `whatelseek/psql_auditor`  
Baseline commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)  
Latest independently reviewed revision: [`eb2ef61`](https://github.com/whatelseek/psql_auditor/commit/eb2ef6130ac17e3f2d7142095045c316ed9a6cbd)  
Total tasks: **77**

## Status summary

| Status | Count |
| --- | ---: |
| Complete `[x]` | **10 / 77 (13.0%)** |
| Partially complete `[~]` | **11 / 77 (14.3%)** |
| Open `[ ]` | **56 / 77 (72.7%)** |
| Not fully complete | **67 / 77 (87.0%)** |

Completed: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`, `CORE-004`, `CORE-005`, `INPUT-001`, `INPUT-003`.

Partially complete: `CORE-006`, `INPUT-002`, `INPUT-004`, `INPUT-005`, `TOOL-001`, `FLOW-007`, `EVID-001`, `EVID-002`, `EVID-003`, `OPS-004`, `DOC-001`.

## Product architecture decision

The target product is a governed AI auditor rather than a catalog of hardcoded
platform branches. Administrators provide versioned inventory, credential
references, human-readable Markdown frameworks, MCP servers, tools, and
capability policies. The LLM uses those resources to plan discovery, collect and
interpret evidence, select every applicable framework, and perform assessments.

The control plane remains deterministic for input validation, credential
protection, tool authorization, read-only enforcement, evidence persistence,
provenance, version/hash pinning, stale-plan rejection, confirmation, and audit
logging. Agent reasoning may be non-deterministic, but the accepted `AuditPlan`
must be reproducible from a pinned inventory, framework catalog, tool catalog,
policy snapshot, and evidence set.

## Latest verification

PR #36 was merged into `main` as commit
[`7be1eae`](https://github.com/whatelseek/psql_auditor/commit/7be1eae717f002612efe5d434d517f5c47a219f1).
PR #37 was merged as
[`eb2ef61`](https://github.com/whatelseek/psql_auditor/commit/eb2ef6130ac17e3f2d7142095045c316ed9a6cbd).
`INPUT-001` and `INPUT-003` remain independently accepted. The Markdown
framework registry is accepted for POC, so `INPUT-002` is `[~]`; two production
hardening findings remain in backlog. `INPUT-005` remains `[~]`.

POC tool-registry vertical slice (this revision): `INPUT-004`, `TOOL-001`,
`EVID-001`, `EVID-002`, and `EVID-003` are `[~]` — SSH is registered through a
validated `ToolRegistry` with capability policy, normalized `ToolResult`,
read-only enforcement, and provenance-bearing evidence. WinRM/HTTP/TCP/SNMP
adapters (`TOOL-002`…`TOOL-005`) remain open. Do not mark `[x]` without
independent acceptance.

| Check | Verified result |
| --- | --- |
| Format | Passed |
| Lint | Passed |
| Type check | Passed, 92 files |
| Unit tests | 473 passed |
| Integration tests | 8 passed |
| Full suite | 481 passed |
| Defect map | `validate-defect-map: OK` (77/77) |

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

`AUD-001` is complete. Checklist v1.14 and the local defect map cover all 77
IDs. `make validate-defect-map` must be rerun in repository CI after this update
is committed.

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
- `AuditRegistry.create_run` / `save_run` validate explicit `audit_run_id` via `require_audit_run_id`;
- warehouse `start_session` / upsert paths require both identifiers;
- `AuditRegistry.save_run` rejects client reassignment;
- resume/bootstrap reject conflicting client ownership;
- legacy API `run_id` means evidence folder, not `audit_run_id`;
- tests reuse AUD-003 fixtures in `tests/test_client_audit_run_identity.py`.

- [x] `CORE-002` — Separate `AuditRun` from `AuditJob`.
- [x] `CORE-003` — Introduce canonical result identity.
- [x] `CORE-004` — Introduce structured `AssessmentResult`.
- [x] `CORE-005` — Isolate checkpoints and artifacts by audit run.

`CORE-005` closure evidence (gap closure):

- `acquire_run_checkpointer` binds compiled graph + checkpointer to
  `client_id` + `audit_run_id` on `runtime._scoped_checkpoints`;
- concurrent `arun_one` captures a local scoped graph; another run cannot
  replace or close its checkpointer;
- canonical Sqlite init failure raises `CheckpointInitError` (no MemorySaver);
- `EvidenceStore.rebind_run_id` validates destination ownership before any
  mkdir/copy/rename and leaves both dirs unchanged on reject;
- regression tests in `tests/test_run_scope_isolation.py`.

- [~] `CORE-006` — Remove hidden global mutable state.

`CORE-006` remains partially complete pending independent acceptance review.
`ApplicationRuntime` ownership is implemented; lifecycle race fixes (lease-aware
MCP pool, truthful task-registry timeouts, balanced checkpoint leases without
force-close, failure-atomic scoped Sqlite init) are ready for acceptance.
Do not mark complete based on class existence alone.

### M2 — Inputs and audit planning

- [x] `INPUT-001` — Introduce a strict `AuditRequest`.

Acceptance evidence:

- strict immutable versioned request model;
- pinned normalized inventory `version_id` and `content_hash`;
- stale requests fail closed at CLI, HTTP, direct execution, and replay boundaries;
- secret-shaped fields are rejected and credentials are resolved at runtime;
- independently accepted on the PR #35 review base carried into merged PR #36.

- [~] `INPUT-002` — Enforce strict validation and registration of text-based frameworks.
- [x] `INPUT-003` — Introduce a validated inventory model.

`INPUT-002` is accepted for POC. Implemented evidence:

- administrator-managed `agents/*.md` registry with no Python change required;
- optional YAML frontmatter; filename/H1/source-hash fallbacks;
- multiline requirement sections and lists;
- compact catalog, compact REQ index, and full body only for the current REQ;
- invalid frameworks remain visible but are not executable;
- prompt retrieval and checklist loading fail closed;
- bundled frameworks remain compatible.

Production-hardening backlog before `[x]`:

- a file beginning with `---` but missing a closing delimiter must produce
  `invalid_frontmatter` and remain non-executable;
- malformed requirement-like headings must produce
  `malformed_requirement_heading` instead of being silently ignored.

The Markdown source remains authoritative.

`INPUT-003` acceptance evidence:

- canonical `ClientInventory`, host, service, fact, and credential-reference models;
- Markdown, YAML, and JSON loaders with typed validation issues;
- stable normalized inventory identity and secret-free persisted payloads;
- independently accepted on the PR #35 review base carried into merged PR #36.

- [~] `INPUT-004` — Introduce an administrator-managed MCP/tool registry and capability policy.

POC partial evidence (independent acceptance still required — do not mark `[x]`):

- versioned tool manifests under `tools/catalog/*.json` with capability,
  risk, schemas, timeout/output limits, and credential-source declarations;
- capability policy snapshot `tools/policies/poc_audit_v1.json`;
- `ToolRegistry` fail-closed validation: invalid tools remain visible but are
  not bound to the LLM (`src/auditor/tool_registry.py`);
- SSH registered through the registry; WinRM/MCP remain transitional;
- each `AuditPlan` / `AuditRun` pins `tool_catalog_hash` and
  `capability_policy_hash`;
- tests: `tests/test_tool_registry.py`.

Current temporary extension paths:

- MCP tool: add `mcps/registry.json` entry, resolve credentials from inventory,
  implement or select curated read-only wrappers, bind them in runtime, and add
  policy/evidence tests;
- built-in tool: add a Python `@tool` adapter under `src/auditor/tools/`, expose
  it through `get_*_tools()`, bind it into audit/discovery runtime, and add tests;
- SSH and WinRM still also exist as hardcoded discovery collectors, so a protocol
  currently has to be integrated in more than one place.

Target extension model after `INPUT-004`:

- known MCP server → registry entry plus capability policy;
- known adapter → versioned manifest under a tool catalog, without graph edits;
- new protocol → one Python adapter plus manifest;
- the manifest declares tool id/version, adapter entrypoint, capabilities, risk,
  input/output schemas, inventory access types, credential source, blocked
  operations, timeout/retry, and output limits;
- registry validation is fail-closed: invalid tools are visible to administrators
  but are not bound to the model;
- each `AuditRun` pins an immutable tool-catalog and capability-policy snapshot;
- the LLM receives only tools authorized for the confirmed target and scope.

### Registered transport and protocol tools

The following tasks implement transport/execution boundaries. They must not
contain technology detection, framework selection, or audit conclusions. The
agent chooses among these tools through `INPUT-004`; deterministic code enforces
scope, authorization, read-only policy, timeouts, credential handling,
sanitation, and provenance.

- [~] `TOOL-001` — Implement a registered SSH execution adapter.
- [ ] `TOOL-002` — Implement a registered WinRM PowerShell adapter.
- [ ] `TOOL-003` — Implement a registered HTTP/HTTPS request adapter.
- [ ] `TOOL-004` — Implement a registered TCP connectivity adapter.
- [ ] `TOOL-005` — Implement a registered SNMP GET/WALK adapter.

`TOOL-001` POC partial evidence (do not mark `[x]` without independent acceptance):

- manifests `tools/catalog/ssh_run.json` and `ssh_read_file.json`;
- adapters `invoke_ssh_run` / `invoke_ssh_read_file` resolve target/credentials
  only from the active inventory/run context (`effective_settings`);
- normalized `ToolResult` with secret-free target + provenance;
- read-only command gate, timeout, output limits, and secret redaction;
- LangChain wrappers remain compatible with existing SSH audit behavior;
- tests: `tests/test_tool_registry.py`.

Common acceptance criteria:

- versioned tool id, input schema, output schema, and capability declaration;
- target authorization and credential references resolved only at runtime;
- normalized `ToolResult` compatible with `EVID-001` and `EVID-003`;
- safe defaults, bounded output, timeout/retry policy, and secret redaction;
- agent-callable only through the registry and active capability-policy snapshot;
- protocol-specific integration tests and failure taxonomy.

Additional `TOOL-002` acceptance criteria:

- structured PowerShell output, preferably `ConvertTo-Json`;
- no `Win32_Product` inventory query;
- TLS certificate validation enabled by default with explicit insecure override;
- correct `LocalPort` parsing without PID contamination;
- real Windows Server/WinRM integration coverage;
- Windows Server and Windows-hosted PostgreSQL E2E framework selection.

- [~] `INPUT-005` — Implement reproducible agentic preflight and `AuditPlan`.

`INPUT-004` acceptance must cover administrator-supplied MCP servers and tools,
versioned schemas/capabilities, read-only and destructive-action policies,
secret-safe invocation, per-run catalog snapshots, and fail-closed authorization.
The LLM may choose among registered capabilities but may not instantiate an
unregistered transport, bypass policy, or execute hidden arbitrary code.

`INPUT-005` partial evidence:

- typed `AuditPlan` with confirmation gate (`src/auditor/domain/audit_plan.py`);
- technology detection + framework selection decisions with reject reasons;
- stale-plan rejection (`plan_stale`) on confirm/start when inventory **or**
  discovery/effective-facts hashes diverge;
- `CREDENTIALS.md` / `credentials.md` / `connection.md` runtime credential
  resolution + secret redaction; `needs_discovery` for IP/port-only hosts;
- transitional `SshDiscoveryCollector` / `WinrmDiscoveryCollector` /
  `CompositeDiscoveryCollector` implementation landed in PR #36; these collectors
  are not the target extensibility boundary and must be migrated to registered
  `TOOL-001` / `TOOL-002` adapters plus a generic discovery workflow;
- current SSH/WinRM discovery commands are read-oriented and PostgreSQL is
  confirmed only with strong evidence, but final invocation policy belongs to
  `INPUT-004`, `EVID-002`, and the protocol tool tasks;
- typed discovery errors, per-host timeout/retry, one-host failure isolation;
- sanitized discovery evidence under `artifacts/<slug>/preflight/…` with
  secret scanning; deterministic preflight revisions;
- CLI sync `start_confirmed_audit` / API `await astart_confirmed_audit` →
  `AuditRequest` → `arun_request` (confirmed start does not silently re-run
  discovery; `--refresh-discovery` optional);
- docs: `docs/inventory-driven-audit.md` (+ RU manual); tests:
  `tests/test_input005_discovery.py`,
  `tests/integration/test_ssh_discovery_container.py`.
  Independent acceptance still required — do not mark `[x]` automatically.

Additional `INPUT-005` acceptance criteria:

- preflight gives the governed LLM the normalized inventory, valid Markdown
  frameworks, registered MCP/tools, and the active capability-policy snapshot;
- the LLM may create and iterate a discovery plan, collect additional evidence,
  identify software/roles/services, and select multiple applicable frameworks;
- framework selection is not limited to hardcoded platform-to-framework maps;
- every selected framework has evidence-backed applicability reasons;
- the final plan pins inventory, framework, tool, policy, and evidence identities;
- the same pinned inputs and accepted evidence produce a stable plan payload;
- uncertain or conflicting conclusions become questions/limitations rather than
  silently invented facts;
- discovery is tool-driven and extensible: adding HTTP, TCP, SNMP, or another
  registered capability does not require a new hardcoded platform collector;
- complete YAML/JSON inventory execution integration and independent acceptance.

### M3 — Governed agent runtime, LangGraph orchestration, and evidence collection

- [ ] `AGENT-001` — Implement the governed LLM agent runtime.

`AGENT-001` acceptance criteria:

- the LLM receives normalized inventory and credential references, never raw
  persisted credentials;
- the LLM receives all valid text frameworks plus registered MCP/tool schemas;
- the LLM can plan discovery, choose authorized tools, interpret outputs, request
  more evidence, identify technologies, and select multiple frameworks;
- every material fact and framework decision references evidence, tool identity,
  collection time, provenance, and confidence;
- deterministic code authorizes calls, enforces read-only policy, sanitizes and
  stores evidence, pins versions/hashes, rejects stale plans, and records an
  audit trail;
- the LLM cannot bypass capability policy, mutate the target, silently expand
  confirmed scope, or execute unregistered code;
- a pinned evidence/catalog snapshot yields a stable final `AuditPlan`, even when
  the internal reasoning trace differs;
- end-to-end tests cover Windows + AD DS, Linux + PostgreSQL, unsupported assets,
  insufficient evidence, MCP/tool failure, and administrator-added frameworks.

- [ ] `FLOW-001` — Make graph state typed and minimal.
- [ ] `FLOW-002` — Replace internal `asyncio.gather` with LangGraph `Send`.
- [ ] `FLOW-003` — Implement a lossless result reducer.
- [ ] `FLOW-004` — Extract a dedicated requirement worker/subgraph.
- [ ] `FLOW-005` — Add timeouts, retries, and backpressure.
- [ ] `FLOW-006` — Implement correct resume and cancellation.
- [~] `FLOW-007` — Remove the process-wide graph singleton.
- [~] `EVID-001` — Normalize tool output.
- [~] `EVID-002` — Enforce read-only behavior and safe invocation.
- [~] `EVID-003` — Preserve provenance for every evidence item.

POC partial evidence for `EVID-001`…`EVID-003` (SSH slice; do not mark `[x]`):

- `ToolResult` schema (`src/auditor/domain/tool_result.py`) with status, output,
  error, tool identity, target, timestamps, and provenance;
- SSH read-only deny-list (`src/auditor/tools/ssh_policy.py`) plus timeout and
  bounded output;
- evidence sidecars write `tool_result.v1` with client/run/framework/requirement
  provenance and catalog/policy hashes (`EvidenceStore.write_tool_result`);
- credentials never appear in arguments/logs/evidence (redaction).

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

- `INPUT-002`: complete the two deferred production-hardening parser findings; `AGENT-001`: finish governed runtime integration.
- `INPUT-004`: complete MCP registration under the unified registry, richer
  capability policies, and independent acceptance of the catalog snapshot.
- `TOOL-001`: independent acceptance of the registered SSH adapter; migrate
  discovery collectors off the hardcoded path.
- `TOOL-002`…`TOOL-005`: extract protocol adapters from hardcoded discovery and
  add WinRM, HTTP, TCP, and SNMP tools.
- `EVID-001`…`EVID-003`: extend normalized ToolResult + provenance beyond SSH
  (WinRM/MCP) and complete independent acceptance.
- `INPUT-005`: migrate to generic tool-driven discovery, complete YAML/JSON execution integration, and pass independent acceptance.
- `FLOW-007`: remove deprecated process-wide graph getters after independent review.
- `DOC-001`: synchronize architecture, tool, and evidence-layout documentation.
- `CI-001`: complete workflow/report/review E2E and migration coverage.

## Status rules

- `[ ]` Open: no acceptance review has confirmed the task.
- `[~]` Partial: meaningful implementation exists, but at least one acceptance
  criterion or proof is missing.
- `[x]` Complete: every acceptance criterion has code/test evidence and the
  required verification has passed.

The Russian checklist
([`psql_auditor_master_refactoring_checklist_ru.md`](psql_auditor_master_refactoring_checklist_ru.md))
is the synchronized detailed status register. This English version remains the
task register for implementation planning and handoff. Both must be updated
together; open items must not be marked accepted without independent review.

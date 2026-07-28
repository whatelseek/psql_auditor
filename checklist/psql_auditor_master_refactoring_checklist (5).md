# `psql_auditor` — Master Development and Acceptance Checklist

Checklist version: **1.15-draft**  
Date: **2026-07-27**  
Repository: `whatelseek/psql_auditor`  
Baseline commit: [`b064e26`](https://github.com/whatelseek/psql_auditor/commit/b064e26e9150d0bf4ebc2036ecc7c839b4b219e4)  
Last independently reviewed revision: [`770fe4e`](https://github.com/whatelseek/psql_auditor/commit/770fe4ebea81de4fc33ee37460c0e3e951d03a7e)  
Total top-level requirements: **77**

This checklist preserves the previous `M0`–`M8` sections, top-level identifiers,
and statuses. Implementation work items are added under every requirement so that
a task specification can target a specific function, expected files can be named
in advance, and acceptance can be performed at a granular level.

Child work items:

- do not increase the total of `77`;
- are not included in the defect map as independent requirements;
- cannot automatically change the parent requirement status;
- may be refined when a task is issued after checking the actual repository structure.

## Status summary

| Status | Count |
|---|---:|
| Accepted `[x]` | **10 / 77 (13.0%)** |
| Partial `[~]` | **11 / 77 (14.3%)** |
| Open `[ ]` | **56 / 77 (72.7%)** |
| Not fully complete | **67 / 77 (87.0%)** |

Accepted: `AUD-001`, `AUD-002`, `AUD-003`, `CORE-001`, `CORE-002`, `CORE-003`,
`CORE-004`, `CORE-005`, `INPUT-001`, `INPUT-003`.

Partial: `CORE-006`, `INPUT-002`, `INPUT-004`, `INPUT-005`, `TOOL-001`,
`FLOW-007`, `EVID-001`, `EVID-002`, `EVID-003`, `OPS-004`, `DOC-001`.

## Child work item statuses

| Status | Meaning |
|---|---|
| `Done` | Implementation is supported by the current code/tests for the parent requirement |
| `Partial` | Only part of the declared scope is implemented |
| `Open` | The work item is not implemented or has not been accepted |
| `Blocked` | Work cannot start until a dependency is completed |
| `Backlog` | Intentionally deferred but retained for production hardening |

## Task specification format

Development work should target one specific child ID:

```text
Implement INPUT005-09 only.
Do not start INPUT005-10 or INPUT005-11.
Modify the declared primary files unless the repository structure requires
a documented alternative.
Update tests and provide acceptance evidence for INPUT005-09.
Do not change parent INPUT-005 to [x].
```

## Product architecture decision

The target product is a governed AI auditor, not a collection of hardcoded
platform-specific branches. An administrator adds versioned inventory,
credential references, human-readable Markdown frameworks, MCP servers, tools,
and capability policies. The LLM uses these resources to plan discovery,
collect and interpret evidence, select every applicable framework, and execute
checks.

The deterministic control plane is responsible for input validation, credential
protection, tool authorization, read-only constraints, evidence persistence,
provenance, pinned versions and hashes, stale-plan rejection, launch
confirmation, and the audit log. Agent reasoning may be nondeterministic, but an
accepted `AuditPlan` must be reproducible from the pinned inventory, framework
catalog, tool catalog, policy snapshot, and evidence set.

## Latest review

PR #40 at head `770fe4e` was independently reviewed as an `INPUT-005` POC slice.
The review confirmed effective inventory, registry-driven SSH discovery,
`HostCapabilitySnapshot`, deterministic technology detection, plan revision,
stale gates, explicit per-host targets, and API/CLI E2E coverage.

`INPUT-005` remains `[~]`: dynamic Markdown framework applicability,
registry-driven TCP/HTTP/SNMP discovery, plan revision pinning in the confirmation
contract, YAML/JSON execution E2E, and the complete agent-driven preflight have
not yet been accepted.

| Check | Result |
|---|---|
| Format / Lint | Passed |
| Type check | Passed |
| Unit tests | 486 passed |
| Integration tests | 8 passed |
| Full suite | 494 passed |
| Defect map | `validate-defect-map: OK` (77/77) |

## Requirement registry

### M0 — Baseline, tests, and CI

- [x] `AUD-001` — Establish a reproducible baseline.

  **Work breakdown:**

  - **`AUD001-01` · `Done`** — Pin the supported Python version, locked dependencies, and installation commands.
    - **Primary files:** `pyproject.toml`, lock file, `README.md`
    - **Acceptance:** A clean environment installs without manual fixes.
  - **`AUD001-02` · `Done`** — Define baseline commands for format, lint, typecheck, unit, integration, and the full suite.
    - **Primary files:** `Makefile`, `pyproject.toml`, `.github/workflows/ci.yml`
    - **Acceptance:** Local and CI commands use the same parameters.
  - **`AUD001-03` · `Done`** — Record baseline test counts and defect-map coverage.
    - **Primary files:** `checklist/`, `scripts/validate_defect_map.py`
    - **Acceptance:** All 77 top-level IDs are covered and the baseline is documented.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [x] `AUD-002` — Use unified local and CI quality gates.

  **Work breakdown:**

  - **`AUD002-01` · `Done`** — Combine format/lint/typecheck/test gates under `make check`.
    - **Primary files:** `Makefile`, `pyproject.toml`
    - **Acceptance:** `make check` returns a non-zero exit code when any gate fails.
  - **`AUD002-02` · `Done`** — Run the same gates in GitHub Actions.
    - **Primary files:** `.github/workflows/ci.yml`
    - **Acceptance:** CI prevents merge when a required job fails.
  - **`AUD002-03` · `Done`** — Add an isolated PostgreSQL integration job.
    - **Primary files:** `.github/workflows/ci.yml`, `tests/integration/`
    - **Acceptance:** Integration tests do not depend on a developer's local database.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [x] `AUD-003` — Provide shared deterministic test fixtures.

  **Work breakdown:**

  - **`AUD003-01` · `Done`** — Create canonical inventory, framework, and evidence fixtures.
    - **Primary files:** `tests/fixtures/`
    - **Acceptance:** Fixtures contain no real secrets and produce stable hashes.
  - **`AUD003-02` · `Done`** — Reuse shared fixtures in unit and integration tests.
    - **Primary files:** `tests/`
    - **Acceptance:** Duplicate local fixtures are removed or explicitly justified.
  - **`AUD003-03` · `Done`** — Add canary secrets for redaction checks.
    - **Primary files:** `tests/fixtures/`, security-focused tests
    - **Acceptance:** Canary values do not appear in payloads, logs, evidence, or exceptions.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

### M1 — Identities and domain model

- [x] `CORE-001` — Separate `client_id` from `audit_run_id`.

  **Work breakdown:**

  - **`CORE001-01` · `Done`** — Introduce separate types/generators for client and run identities.
    - **Primary files:** `src/auditor/domain/`, `src/auditor/client_registry.py`, `src/auditor/audit_registry.py`
    - **Acceptance:** Client identity is never reused as run identity.
  - **`CORE001-02` · `Done`** — Propagate both identities through API, CLI, graph, and persistence layers.
    - **Primary files:** `src/auditor/api/`, `src/auditor/cli.py`, `src/auditor/graph.py`
    - **Acceptance:** Every runtime record contains the correct client/run references.
  - **`CORE001-03` · `Done`** — Add regression tests for identity mixing.
    - **Primary files:** `tests/test_identity*.py`
    - **Acceptance:** Supplying `client_id` where `audit_run_id` is required is rejected.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [x] `CORE-002` — Separate `AuditRun` from `AuditJob`.

  **Work breakdown:**

  - **`CORE002-01` · `Done`** — Define separate domain models for a run and a job.
    - **Primary files:** `src/auditor/domain/audit_models.py`
    - **Acceptance:** A run stores launch lifecycle data; a job stores one execution unit.
  - **`CORE002-02` · `Done`** — Separate persistence and transitions.
    - **Primary files:** `src/auditor/audit_registry.py`
    - **Acceptance:** Job transitions do not modify other jobs or replace run status.
  - **`CORE002-03` · `Done`** — Cover multi-host and multi-framework jobs.
    - **Primary files:** `tests/test_audit_registry*.py`
    - **Acceptance:** One run contains independent jobs with stable IDs.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [x] `CORE-003` — Define canonical result identity.

  **Work breakdown:**

  - **`CORE003-01` · `Done`** — Derive result identity from run/job/host/framework/requirement.
    - **Primary files:** `src/auditor/domain/`, result persistence modules
    - **Acceptance:** The same assessment cannot produce ambiguous result keys.
  - **`CORE003-02` · `Done`** — Use the identity in every write/read path.
    - **Primary files:** `src/auditor/evidence_store.py`, reporting inputs, repositories
    - **Acceptance:** A result can be retrieved unambiguously by canonical key.
  - **`CORE003-03` · `Done`** — Add duplicate/replay regression coverage.
    - **Primary files:** `tests/test_result_identity*.py`
    - **Acceptance:** Replay does not create conflicting or duplicate results.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [x] `CORE-004` — Introduce structured `AssessmentResult`.

  **Work breakdown:**

  - **`CORE004-01` · `Done`** — Define typed status, observation, recommendation, and evidence fields.
    - **Primary files:** `src/auditor/domain/assessment_result.py` or the current domain module
    - **Acceptance:** An invalid status or missing identity is rejected.
  - **`CORE004-02` · `Done`** — Remove free-form dictionaries from the canonical persistence path.
    - **Primary files:** assessment workflow and persistence modules
    - **Acceptance:** Only a validated domain object is persisted.
  - **`CORE004-03` · `Done`** — Add JSON round-trip and schema tests.
    - **Primary files:** `tests/test_assessment_result*.py`
    - **Acceptance:** Serialization is stable and backward-compatible within the schema version.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [x] `CORE-005` — Isolate checkpoints and artifacts by audit run.

  **Work breakdown:**

  - **`CORE005-01` · `Done`** — Use `audit_run_id` in the checkpoint namespace.
    - **Primary files:** `src/auditor/graph.py`, checkpoint/runtime modules
    - **Acceptance:** Two runs for the same client do not share state.
  - **`CORE005-02` · `Done`** — Separate evidence/report/archive directories by run.
    - **Primary files:** `src/auditor/evidence_store.py`, archive/report modules
    - **Acceptance:** Artifacts from different runs do not overwrite each other.
  - **`CORE005-03` · `Done`** — Add a parallel-run regression test.
    - **Primary files:** `tests/test_run_isolation*.py`
    - **Acceptance:** Parallel runs do not read or modify each other's data.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [~] `CORE-006` — Remove hidden global mutable state.

  **Work breakdown:**

  - **`CORE006-01` · `Done`** — Introduce `ApplicationRuntime` and dependency injection for graph/settings/registries.
    - **Primary files:** `src/auditor/application_runtime.py`, `src/auditor/api/app.py`
    - **Acceptance:** The main API lifecycle explicitly creates and closes the runtime.
  - **`CORE006-02` · `Partial`** — Remove process-wide cached registries where an immutable per-run snapshot is required.
    - **Primary files:** `src/auditor/tool_registry.py`, framework/client registries
    - **Acceptance:** A run uses a pinned snapshot rather than a mutable singleton.
  - **`CORE006-03` · `Open`** — Delete deprecated global graph getters and hidden module-level mutable objects.
    - **Primary files:** `src/auditor/graph.py`, `src/auditor/api/`, compatibility modules
    - **Acceptance:** The production path does not depend on a process-wide singleton.
  - **`CORE006-04` · `Open`** — Add concurrency and lifecycle acceptance tests.
    - **Primary files:** `tests/test_application_runtime*.py`
    - **Acceptance:** Multiple runtime instances operate and shut down independently.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

### M2 — Inputs and audit planning

- [x] `INPUT-001` — Enforce strict `AuditRequest`.

  **Work breakdown:**

  - **`INPUT001-01` · `Done`** — Define an immutable versioned request schema.
    - **Primary files:** `src/auditor/domain/audit_request.py`
    - **Acceptance:** Unknown fields, secret-shaped fields, and invalid values are rejected.
  - **`INPUT001-02` · `Done`** — Pin inventory version/content hash and target/framework identities.
    - **Primary files:** `src/auditor/domain/audit_request.py`, request validation
    - **Acceptance:** Stale inventory fails closed in API, CLI, direct execution, and replay paths.
  - **`INPUT001-03` · `Done`** — Resolve credentials only at runtime.
    - **Primary files:** `src/auditor/effective_settings.py`, inventory/runtime modules
    - **Acceptance:** Secrets are absent from request payloads and persistence.
  - **`INPUT001-04` · `Done`** — Cover Markdown/YAML/JSON request-ingress regressions.
    - **Primary files:** `tests/test_inventory_driven_audit.py`
    - **Acceptance:** Every supported input creates an equivalently validated request.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [~] `INPUT-002` — Strictly validate and register text frameworks.

  **Work breakdown:**

  - **`INPUT002-01` · `Done`** — Load Markdown frameworks from `agents/` and extract ID/title/version/hash.
    - **Primary files:** `src/auditor/frameworks.py`, `agents/`
    - **Acceptance:** A new basic Markdown framework is visible without changing core Python.
  - **`INPUT002-02` · `Done`** — Keep invalid frameworks in the catalog as non-executable entries with validation issues.
    - **Primary files:** `src/auditor/frameworks.py`, registry tests
    - **Acceptance:** One invalid file does not break the valid catalog.
  - **`INPUT002-03` · `Open`** — Add typed front matter for applicability, required facts/capabilities, and discovery hints.
    - **Primary files:** `src/auditor/domain/framework_applicability.py` (new), `src/auditor/frameworks.py`
    - **Acceptance:** Metadata passes schema validation without executable expressions.
  - **`INPUT002-04` · `Open`** — Close deferred parser hardening for ambiguous headings, duplicate IDs/requirements, and unsafe metadata.
    - **Primary files:** `src/auditor/frameworks.py`, `tests/test_framework_registry.py`
    - **Acceptance:** The parser fails closed and reports precise issues.
  - **`INPUT002-05` · `Open`** — Add a compatibility/versioning contract for the framework schema.
    - **Primary files:** `src/auditor/domain/`, docs, tests
    - **Acceptance:** An incompatible schema version is rejected with a clear error.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [x] `INPUT-003` — Provide a validated inventory model.

  **Work breakdown:**

  - **`INPUT003-01` · `Done`** — Define typed client/host/service/fact/credential-reference models.
    - **Primary files:** `src/auditor/domain/inventory.py`
    - **Acceptance:** The domain model does not store raw secrets.
  - **`INPUT003-02` · `Done`** — Support Markdown, YAML, and JSON loaders.
    - **Primary files:** `src/auditor/inventory/loaders.py`, `normalize.py`
    - **Acceptance:** All formats normalize into one model.
  - **`INPUT003-03` · `Done`** — Add stable `version_id`/`content_hash` and typed validation issues.
    - **Primary files:** inventory domain/service modules
    - **Acceptance:** The same effective input has the same identity.
  - **`INPUT003-04` · `Done`** — Add fixtures and cross-format tests.
    - **Primary files:** `tests/fixtures/inventory/`, `tests/test_inventory_driven_audit.py`
    - **Acceptance:** Cross-format values and errors are equivalent.

  **Parent status rule:** the requirement was independently accepted; child `Done` items document the accepted implementation.

- [~] `INPUT-004` — Administrator-managed MCP/tool registry and capability policy.

  **Work breakdown:**

  - **`INPUT004-01` · `Done`** — Introduce versioned tool manifests and fail-closed registry validation.
    - **Primary files:** `src/auditor/tool_registry.py`, `tools/catalog/`, `tests/test_tool_registry.py`
    - **Acceptance:** An invalid tool remains visible but is neither executable nor bindable.
  - **`INPUT004-02` · `Done`** — Introduce capability-policy snapshots and hashes.
    - **Primary files:** `tools/policies/`, tool registry/domain modules
    - **Acceptance:** Plans and runs pin `tool_catalog_hash` and `capability_policy_hash`.
  - **`INPUT004-03` · `Partial`** — Unify built-in adapters and MCP registrations in one catalog.
    - **Primary files:** `src/auditor/tool_registry.py`, `mcps/registry.json`, adapter modules
    - **Acceptance:** Both tool types use the same validation and authorization model.
  - **`INPUT004-04` · `Open`** — Add administrator-facing install/update/disable lifecycle operations for manifests.
    - **Primary files:** registry service/API/CLI, docs
    - **Acceptance:** Catalog changes create a new immutable snapshot identity.
  - **`INPUT004-05` · `Open`** — Apply manifest timeout/retry/output limits at runtime for every adapter.
    - **Primary files:** tool invocation/runtime modules
    - **Acceptance:** Runtime execution does not ignore manifest limits.
  - **`INPUT004-06` · `Backlog`** — Close hardening findings: empty allow-list deny-all, hash propagation/freeze, and adapter import visibility.
    - **Primary files:** `src/auditor/tool_registry.py`, invocation tests
    - **Acceptance:** Every known production backlog finding is closed.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [~] `TOOL-001` — Registered SSH execution adapter.

  **Work breakdown:**

  - **`TOOL001-01` · `Done`** — Provide `ssh_run` and `ssh_read_file` manifests, schemas, and capabilities.
    - **Primary files:** `tools/catalog/ssh_run.json`, `ssh_read_file.json`
    - **Acceptance:** The registry validates and publishes both operations.
  - **`TOOL001-02` · `Done`** — Resolve runtime targets and credentials only from active inventory/run context.
    - **Primary files:** SSH adapter modules, `effective_settings`
    - **Acceptance:** The LLM cannot provide an arbitrary host or credential.
  - **`TOOL001-03` · `Done`** — Enforce a strict command allow-list, path gate, redaction, and normalized `ToolResult`.
    - **Primary files:** `src/auditor/tools/ssh_policy.py`, SSH adapters
    - **Acceptance:** Shell composition, interpreters, and prohibited paths are blocked.
  - **`TOOL001-04` · `Backlog`** — Protect `ssh_read_file` from symlink bypass.
    - **Primary files:** SSH adapter/policy tests
    - **Acceptance:** An allowed symlink pointing to a prohibited file cannot be read.
  - **`TOOL001-05` · `Backlog`** — Fully apply manifest timeout/max-output/retry and immutable hash snapshot.
    - **Primary files:** tool invocation/runtime modules
    - **Acceptance:** The real execution path uses pinned limits and hashes.
  - **`TOOL001-06` · `Open`** — Perform independent acceptance against a real SSH target.
    - **Primary files:** integration/E2E tests
    - **Acceptance:** The adapter is confirmed outside a fake transport.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [ ] `TOOL-002` — Registered WinRM PowerShell adapter.

  **Work breakdown:**

  - **`TOOL002-01` · `Open`** — Define manifests, capabilities, and PowerShell operation IDs.
    - **Primary files:** `tools/catalog/winrm_*.json` (new), policy
    - **Acceptance:** Only read-only operations are available.
  - **`TOOL002-02` · `Open`** — Implement a WinRM adapter with TLS validation and runtime credentials.
    - **Primary files:** `src/auditor/tools/adapters/winrm.py` (new)
    - **Acceptance:** Insecure mode is available only through an explicit policy-controlled override.
  - **`TOOL002-03` · `Open`** — Normalize structured PowerShell JSON output and typed errors.
    - **Primary files:** WinRM adapter/domain result modules
    - **Acceptance:** `Win32_Product` is not used; `LocalPort` is not confused with PID.
  - **`TOOL002-04` · `Open`** — Add fake and real Windows integration tests.
    - **Primary files:** `tests/test_winrm_tool.py`, integration fixtures
    - **Acceptance:** Windows Server and PostgreSQL-on-Windows E2E scenarios pass.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `TOOL-003` — Registered HTTP/HTTPS request adapter.

  **Work breakdown:**

  - **`TOOL003-01` · `Open`** — Define manifests for GET/HEAD with bounded responses.
    - **Primary files:** `tools/catalog/http_get.json` (new), policy
    - **Acceptance:** POST/PUT/PATCH/DELETE are unavailable.
  - **`TOOL003-02` · `Open`** — Implement an adapter with target scope, TLS, and redirect restrictions.
    - **Primary files:** `src/auditor/tools/adapters/http.py` (new)
    - **Acceptance:** Redirects cannot leave the approved host/scope.
  - **`TOOL003-03` · `Open`** — Redact headers/cookies/tokens and normalize status/header/body metadata.
    - **Primary files:** HTTP adapter, `ToolResult` normalizer
    - **Acceptance:** Secret headers are never persisted.
  - **`TOOL003-04` · `Open`** — Add a local HTTP fixture and integration tests.
    - **Primary files:** `tests/test_http_tool.py`, test server fixture
    - **Acceptance:** Timeout, size limit, TLS errors, and redirects are covered.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `TOOL-004` — Registered TCP connectivity adapter.

  **Work breakdown:**

  - **`TOOL004-01` · `Open`** — Define a `tcp.connect` manifest with a bounded list of ports.
    - **Primary files:** `tools/catalog/tcp_connect.json` (new), policy
    - **Acceptance:** Only policy-approved ports are checked per host.
  - **`TOOL004-02` · `Open`** — Implement the adapter; keep direct socket calls only inside it.
    - **Primary files:** `src/auditor/tools/adapters/tcp.py` (new)
    - **Acceptance:** Workflow code does not import `socket` directly.
  - **`TOOL004-03` · `Open`** — Normalize open/closed/timeout/unreachable facts.
    - **Primary files:** TCP adapter, fact normalizer
    - **Acceptance:** Errors are distinguishable and secret-free.
  - **`TOOL004-04` · `Open`** — Add integration tests using local open and closed ports.
    - **Primary files:** `tests/test_tcp_tool.py`
    - **Acceptance:** Subnet scanning and target override are impossible.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `TOOL-005` — Registered SNMP GET/WALK adapter.

  **Work breakdown:**

  - **`TOOL005-01` · `Open`** — Define SNMP GET/WALK manifests and an OID allow-list.
    - **Primary files:** `tools/catalog/snmp_get.json`, `snmp_walk.json` (new), policy
    - **Acceptance:** SNMP SET is unavailable.
  - **`TOOL005-02` · `Open`** — Implement an SNMPv3-first adapter with runtime secret resolution.
    - **Primary files:** `src/auditor/tools/adapters/snmp.py` (new)
    - **Acceptance:** Community strings and authentication keys do not enter LLM context or evidence.
  - **`TOOL005-03` · `Open`** — Bound walk prefix/output/time and normalize vendor/model/platform facts.
    - **Primary files:** SNMP adapter/fact normalizer
    - **Acceptance:** Walk operations cannot leave policy-approved OID prefixes.
  - **`TOOL005-04` · `Open`** — Add a fake agent and optional real integration tests.
    - **Primary files:** `tests/test_snmp_tool.py`
    - **Acceptance:** Cisco discovery works without a Python framework mapping.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [~] `INPUT-005` — Reproducible agent-driven preflight and `AuditPlan`.

  **Work breakdown:**

  - **`INPUT005-01` · `Done`** — Validate and normalize inventory; prevent discovery when errors exist.
    - **Primary files:** inventory domain/loaders/service tests
    - **Acceptance:** Invalid inventory does not start probes.
  - **`INPUT005-02` · `Done`** — Persist and reload effective inventory for confirm/start.
    - **Primary files:** `src/auditor/inventory/service.py`, API routes
    - **Acceptance:** Discovery facts survive the complete lifecycle.
  - **`INPUT005-03` · `Done`** — Registry-authorized SSH discovery without `_tcp_reachable`.
    - **Primary files:** `src/auditor/inventory/collectors.py`, `tool_discovery.py`
    - **Acceptance:** The SSH adapter classifies failures.
  - **`INPUT005-04` · `Done`** — Create `HostCapabilitySnapshot` for supported and unsupported assets.
    - **Primary files:** host capability domain/tool discovery
    - **Acceptance:** Every asset remains visible.
  - **`INPUT005-05` · `Done`** — Use one deterministic technology-detection model.
    - **Primary files:** `src/auditor/inventory/detect.py`, snapshot sync
    - **Acceptance:** Port-only PostgreSQL is `suspected`.
  - **`INPUT005-06` · `Done`** — Provide deterministic `AuditPlan`, stale gates, confirmation, and plan-to-job identity.
    - **Primary files:** audit plan/service/API modules
    - **Acceptance:** Jobs are created only after confirmation and match plan targets.
  - **`INPUT005-07` · `Backlog`** — Pin `plan_revision_id` in API/CLI confirm/start contracts.
    - **Primary files:** `src/auditor/api/inventory_routes.py`, service/domain tests
    - **Acceptance:** A previously displayed revision cannot confirm a newer latest plan.
  - **`INPUT005-08` · `Backlog`** — Store plans and effective inventory immutably by revision.
    - **Primary files:** inventory plan/service persistence
    - **Acceptance:** Earlier revisions remain retrievable and are never overwritten.
  - **`INPUT005-09` · `Open`** — Add a typed applicability metadata schema to Markdown frameworks.
    - **Primary files:** `src/auditor/domain/framework_applicability.py` (new), `frameworks.py`
    - **Acceptance:** Invalid metadata is non-executable.
  - **`INPUT005-10` · `Open`** — Implement a safe `all/any/none` predicate evaluator without executable expressions.
    - **Primary files:** `src/auditor/framework_applicability.py` (new)
    - **Acceptance:** An unknown fact produces `missing_evidence`.
  - **`INPUT005-11` · `Open`** — Define a stable normalized fact namespace with source/confidence/evidence.
    - **Primary files:** `src/auditor/inventory/facts.py` (new)
    - **Acceptance:** Predicates never read raw tool output.
  - **`INPUT005-12` · `Open`** — Evaluate framework candidates for every host/framework pair.
    - **Primary files:** `src/auditor/inventory/framework_candidates.py` (new)
    - **Acceptance:** `not_matched` candidates do not trigger discovery.
  - **`INPUT005-13` · `Open`** — Remove the production dependency on hardcoded platform mapping.
    - **Primary files:** `src/auditor/inventory/select_frameworks.py`, `agents/*.md`
    - **Acceptance:** A new Markdown framework can be selected without Python changes.
  - **`INPUT005-14` · `Open`** — Build a typed capability-based discovery plan from missing facts.
    - **Primary files:** `src/auditor/domain/discovery_plan.py`, `inventory/discovery_plan.py` (new)
    - **Acceptance:** The planner requests a capability, not a protocol client.
  - **`INPUT005-15` · `Open`** — Integrate the TCP discovery capability.
    - **Primary files:** TOOL-004 files plus discovery plan
    - **Acceptance:** Port facts are collected through the registry.
  - **`INPUT005-16` · `Open`** — Integrate the HTTP discovery capability.
    - **Primary files:** TOOL-003 files plus discovery plan
    - **Acceptance:** HTTP facts are collected through the registry.
  - **`INPUT005-17` · `Open`** — Integrate the SNMP discovery capability.
    - **Primary files:** TOOL-005 files plus discovery plan
    - **Acceptance:** Cisco facts and selection are not hardcoded.
  - **`INPUT005-18` · `Open`** — Add evidence-backed framework-selection provenance.
    - **Primary files:** selection/domain/plan modules
    - **Acceptance:** Every selected framework records facts, tools, evidence references, and confidence.
  - **`INPUT005-19` · `Open`** — Add an operator clarification loop for missing/conflicting evidence.
    - **Primary files:** audit plan/service/API modules
    - **Acceptance:** An operator response creates a new plan revision with provenance.
  - **`INPUT005-20` · `Open`** — Markdown plug-in E2E: Redis framework without Python changes.
    - **Primary files:** `agents/redis_health.md` fixture, dynamic framework tests
    - **Acceptance:** The framework is selected only for Redis hosts.
  - **`INPUT005-21` · `Open`** — Multi-protocol discovery E2E for TCP/HTTP/SNMP.
    - **Primary files:** dynamic discovery E2E tests
    - **Acceptance:** A blocked capability remains visible.
  - **`INPUT005-22` · `Open`** — Markdown/YAML/JSON execution E2E.
    - **Primary files:** inventory fixtures/E2E tests
    - **Acceptance:** All formats produce equivalent effective plans and jobs.
  - **`INPUT005-23` · `Open`** — Independent acceptance and parent transition to `[x]`.
    - **Primary files:** checklists, defect map, CI evidence
    - **Acceptance:** All mandatory items are `Done`, CI is green, and defect-map coverage is 77/77.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

### M3 — Governed agent, LangGraph, and evidence collection

- [ ] `AGENT-001` — Implement a governed LLM agent runtime.

  **Work breakdown:**

  - **`AGENT001-01` · `Open`** — Define typed agent input/output contracts and allowed context.
    - **Primary files:** `src/auditor/domain/agent.py` (new), prompts/runtime
    - **Acceptance:** Raw credentials are excluded from model context.
  - **`AGENT001-02` · `Open`** — Provide inventory, framework catalog, tool schemas, and policy snapshot to the agent.
    - **Primary files:** agent runtime/context builder
    - **Acceptance:** Context is pinned and versioned.
  - **`AGENT001-03` · `Open`** — Implement a discovery-planning/tool-selection loop with structured outputs.
    - **Primary files:** agent nodes/subgraph
    - **Acceptance:** The LLM proposes only registered capabilities.
  - **`AGENT001-04` · `Open`** — Deterministically validate facts, decisions, and `AuditPlan`.
    - **Primary files:** agent validators plus INPUT-005 modules
    - **Acceptance:** The LLM cannot expand scope or confirm the plan.
  - **`AGENT001-05` · `Open`** — Add HITL questions and continuation after an operator response.
    - **Primary files:** API/OpenWebUI integration, graph state
    - **Acceptance:** Responses create auditable state transitions.
  - **`AGENT001-06` · `Open`** — E2E: Windows+AD DS, Linux+PostgreSQL, unsupported assets, tool failure, and a custom framework.
    - **Primary files:** `tests/test_agent_e2e.py` (new)
    - **Acceptance:** Every scenario produces evidence-backed decisions.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `FLOW-001` — Define minimal typed graph state.

  **Work breakdown:**

  - **`FLOW001-01` · `Open`** — Define immutable/typed graph-state fields.
    - **Primary files:** `src/auditor/domain/graph_state.py` (new)
    - **Acceptance:** No untyped catch-all state dictionary remains.
  - **`FLOW001-02` · `Open`** — Separate run-level and worker-level state.
    - **Primary files:** graph/subgraph modules
    - **Acceptance:** Workers cannot overwrite shared state incorrectly.
  - **`FLOW001-03` · `Open`** — Add serialization/checkpoint round-trip tests.
    - **Primary files:** `tests/test_graph_state.py`
    - **Acceptance:** State is restored without identity loss.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `FLOW-002` — Replace `asyncio.gather` with LangGraph `Send`.

  **Work breakdown:**

  - **`FLOW002-01` · `Open`** — Build fan-out payloads by host/framework/requirement.
    - **Primary files:** graph orchestration modules
    - **Acceptance:** Every `Send` carries canonical job identity.
  - **`FLOW002-02` · `Open`** — Implement fan-in through a reducer.
    - **Primary files:** graph builder/reducer modules
    - **Acceptance:** Results do not depend on completion order.
  - **`FLOW002-03` · `Open`** — Add concurrency and backpressure tests.
    - **Primary files:** `tests/test_graph_send.py`
    - **Acceptance:** Parallelism limits are enforced.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `FLOW-003` — Implement a lossless result reducer.

  **Work breakdown:**

  - **`FLOW003-01` · `Open`** — Define reducer keys and merge semantics.
    - **Primary files:** `src/auditor/graph_reducers.py` (new)
    - **Acceptance:** Duplicate result identity is handled deterministically.
  - **`FLOW003-02` · `Open`** — Preserve partial results and errors without hidden loss.
    - **Primary files:** reducer and domain models
    - **Acceptance:** One failed worker does not remove successful results.
  - **`FLOW003-03` · `Open`** — Add order-independent property tests.
    - **Primary files:** `tests/test_graph_reducers.py`
    - **Acceptance:** Reordering results does not change final state.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `FLOW-004` — Create a dedicated requirement worker/subgraph.

  **Work breakdown:**

  - **`FLOW004-01` · `Open`** — Extract the requirement-worker lifecycle.
    - **Primary files:** `src/auditor/workflows/requirement_worker.py` (new)
    - **Acceptance:** Load→tools→evidence→assess→persist is isolated.
  - **`FLOW004-02` · `Open`** — Pass only scoped tools and evidence.
    - **Primary files:** worker/context modules
    - **Acceptance:** A worker cannot see unrelated hosts/frameworks.
  - **`FLOW004-03` · `Open`** — Add unit tests for success/blocked/error/partial paths.
    - **Primary files:** `tests/test_requirement_worker.py`
    - **Acceptance:** Transitions and outputs are typed.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `FLOW-005` — Add timeouts, retries, and backpressure.

  **Work breakdown:**

  - **`FLOW005-01` · `Open`** — Define typed retry policy by error taxonomy.
    - **Primary files:** workflow retry module
    - **Acceptance:** Policy-denied, authentication, and invalid-argument errors are not retried.
  - **`FLOW005-02` · `Open`** — Add per-tool/per-worker timeout and maximum attempts.
    - **Primary files:** graph/tool runtime
    - **Acceptance:** Stuck operations terminate within bounded limits.
  - **`FLOW005-03` · `Open`** — Add global and per-host concurrency limits.
    - **Primary files:** graph scheduler/settings
    - **Acceptance:** Limits are configurable and tested.
  - **`FLOW005-04` · `Open`** — Add load/failure regression tests.
    - **Primary files:** `tests/test_flow_resilience.py`
    - **Acceptance:** No retry storm or unbounded queue occurs.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `FLOW-006` — Implement correct resume and cancellation.

  **Work breakdown:**

  - **`FLOW006-01` · `Open`** — Checkpoint completed, interrupted, and pending jobs.
    - **Primary files:** graph checkpoint modules
    - **Acceptance:** Completed jobs are not executed again.
  - **`FLOW006-02` · `Open`** — Resume an interrupted worker with a new attempt identity.
    - **Primary files:** workflow/job registry
    - **Acceptance:** Attempt history is preserved.
  - **`FLOW006-03` · `Open`** — Add cancellation state and stop-new-work semantics.
    - **Primary files:** API/CLI/graph lifecycle
    - **Acceptance:** New `Send` operations are not created after cancellation.
  - **`FLOW006-04` · `Open`** — Add E2E cancellation/resume tests.
    - **Primary files:** `tests/test_resume_cancel.py`
    - **Acceptance:** A run reaches the correct terminal state.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [~] `FLOW-007` — Remove the process-wide graph singleton.

  **Work breakdown:**

  - **`FLOW007-01` · `Done`** — Create the graph through `ApplicationRuntime` in the API runtime.
    - **Primary files:** `src/auditor/application_runtime.py`, API app
    - **Acceptance:** The FastAPI path does not require a global graph.
  - **`FLOW007-02` · `Partial`** — Move CLI/tests to an explicit graph factory/dependency.
    - **Primary files:** CLI/compatibility/test modules
    - **Acceptance:** New call sites do not use singleton getters.
  - **`FLOW007-03` · `Open`** — Delete deprecated process-wide getters/cache.
    - **Primary files:** `src/auditor/graph.py` and exports
    - **Acceptance:** No singleton graph remains in production code.
  - **`FLOW007-04` · `Open`** — Add lifecycle acceptance for multiple graph instances.
    - **Primary files:** runtime tests
    - **Acceptance:** Instances do not share mutable state.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [~] `EVID-001` — Normalize tool output.

  **Work breakdown:**

  - **`EVID001-01` · `Done`** — Define `ToolResult` v1 for the SSH slice.
    - **Primary files:** `src/auditor/domain/tool_result.py`
    - **Acceptance:** Status, output, error, identity, and timestamps are present.
  - **`EVID001-02` · `Open`** — Apply `ToolResult` to every registered adapter and MCP tool.
    - **Primary files:** tool adapters/MCP wrappers
    - **Acceptance:** No transport-specific raw dictionary enters the workflow.
  - **`EVID001-03` · `Open`** — Version normalizers and output schemas.
    - **Primary files:** domain/normalizer registry
    - **Acceptance:** Invalid adapter output fails closed.
  - **`EVID001-04` · `Open`** — Add cross-protocol contract tests.
    - **Primary files:** `tests/test_tool_result_contract.py`
    - **Acceptance:** SSH/WinRM/HTTP/TCP/SNMP/MCP produce compatible shapes.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [~] `EVID-002` — Enforce read-only behavior and safe invocation.

  **Work breakdown:**

  - **`EVID002-01` · `Done`** — Enforce SSH strict allow-list and path restrictions.
    - **Primary files:** SSH policy/adapter tests
    - **Acceptance:** Dangerous commands are blocked.
  - **`EVID002-02` · `Open`** — Define one risk/read-only policy for every capability.
    - **Primary files:** capability policy/domain modules
    - **Acceptance:** A dangerous operation requires a separate explicit policy.
  - **`EVID002-03` · `Open`** — Add pre/post invocation guards for target, arguments, and output.
    - **Primary files:** tool execution workflow
    - **Acceptance:** The LLM cannot bypass policy through arguments.
  - **`EVID002-04` · `Backlog`** — Close SSH symlink and other protocol-hardening findings.
    - **Primary files:** adapter-specific tests
    - **Acceptance:** Known bypasses are eliminated.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [~] `EVID-003` — Add provenance to every evidence item.

  **Work breakdown:**

  - **`EVID003-01` · `Done`** — Include client/run/framework/requirement and hashes in SSH sidecars.
    - **Primary files:** evidence store/tool execution
    - **Acceptance:** Basic provenance is available.
  - **`EVID003-02` · `Open`** — Add tool/version/capability/target/attempt/timestamps for every source.
    - **Primary files:** evidence domain/store
    - **Acceptance:** Every fact can be traced to an invocation.
  - **`EVID003-03` · `Open`** — Link normalized facts and framework decisions to evidence references.
    - **Primary files:** INPUT-005 fact/selection modules
    - **Acceptance:** A selected framework has a verifiable evidence chain.
  - **`EVID003-04` · `Open`** — Add tamper and missing-provenance validation tests.
    - **Primary files:** `tests/test_evidence_provenance.py`
    - **Acceptance:** Evidence without required provenance is rejected.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [ ] `EVID-004` — Use structured output instead of fragile JSON parsing.

  **Work breakdown:**

  - **`EVID004-01` · `Open`** — Define Pydantic/JSON Schema outputs for LLM nodes.
    - **Primary files:** domain agent/assessment schemas
    - **Acceptance:** Free-form JSON extraction is removed.
  - **`EVID004-02` · `Open`** — Use provider structured output or a constrained parser.
    - **Primary files:** LLM adapter/runtime
    - **Acceptance:** Schema violations produce a typed error/retry.
  - **`EVID004-03` · `Open`** — Add regression coverage for malformed/partial model output.
    - **Primary files:** tests
    - **Acceptance:** Invalid output cannot enter results.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `EVID-005` — Evaluate evidence sufficiency and confidence.

  **Work breakdown:**

  - **`EVID005-01` · `Open`** — Define evidence requirements by requirement/framework.
    - **Primary files:** framework metadata/domain
    - **Acceptance:** Minimum sources and freshness are explicit.
  - **`EVID005-02` · `Open`** — Calculate deterministic sufficiency/confidence.
    - **Primary files:** evidence evaluator module
    - **Acceptance:** The LLM explanation does not change the score.
  - **`EVID005-03` · `Open`** — Block final conclusions when evidence is insufficient.
    - **Primary files:** assessment workflow
    - **Acceptance:** Status becomes `unknown` or `needs_evidence`.
  - **`EVID005-04` · `Open`** — Add tests for strong, weak, and conflicting evidence.
    - **Primary files:** tests
    - **Acceptance:** Confidence boundaries are reproducible.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `EVID-006` — Protect immutable framework fields.

  **Work breakdown:**

  - **`EVID006-01` · `Open`** — Separate immutable framework cells from model-filled cells.
    - **Primary files:** framework/assessment domain
    - **Acceptance:** ID, title, category, severity, and pass criteria cannot change.
  - **`EVID006-02` · `Open`** — Validate results against the pinned framework hash.
    - **Primary files:** assessment persistence
    - **Acceptance:** A result from another framework revision is rejected.
  - **`EVID006-03` · `Open`** — Add mutation/adversarial tests.
    - **Primary files:** tests
    - **Acceptance:** The LLM cannot rewrite immutable metadata.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `EVID-007` — Prevent hidden data loss during truncation.

  **Work breakdown:**

  - **`EVID007-01` · `Open`** — Define explicit truncation metadata and original size/hash.
    - **Primary files:** ToolResult/evidence domain
    - **Acceptance:** Truncated output is explicitly marked.
  - **`EVID007-02` · `Open`** — Store the full raw artifact separately when policy permits.
    - **Primary files:** evidence store
    - **Acceptance:** Assessment uses a bounded view while raw data remains available by reference.
  - **`EVID007-03` · `Open`** — Add chunk/continuation strategy for important data.
    - **Primary files:** tool/evidence workflow
    - **Acceptance:** No silent tail loss occurs.
  - **`EVID007-04` · `Open`** — Add boundary-size and secret-redaction tests.
    - **Primary files:** tests
    - **Acceptance:** Truncation neither exposes nor silently hides critical data without a marker.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

### M4 — PostgreSQL, history, and exceptions

- [ ] `DB-001` — Add versioned database migrations.

  **Work breakdown:**

  - **`DB001-01` · `Open`** — Select a migration framework and define the baseline schema.
    - **Primary files:** `alembic.ini`, `migrations/` (new), DB settings
    - **Acceptance:** A new database is initialized with one command.
  - **`DB001-02` · `Open`** — Add migrations for clients/runs/jobs/results/evidence/exceptions.
    - **Primary files:** migration files
    - **Acceptance:** The schema reflects canonical identities.
  - **`DB001-03` · `Open`** — Add upgrade/downgrade and CI migration tests.
    - **Primary files:** integration tests/CI
    - **Acceptance:** Migrations are reproducible on PostgreSQL.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `DB-002` — Define repositories and transaction boundaries.

  **Work breakdown:**

  - **`DB002-01` · `Open`** — Define repository interfaces and a unit of work.
    - **Primary files:** `src/auditor/repositories/` (new)
    - **Acceptance:** The domain layer does not depend directly on a SQLAlchemy session.
  - **`DB002-02` · `Open`** — Implement PostgreSQL repositories.
    - **Primary files:** repository implementations
    - **Acceptance:** Writes are atomic within declared boundaries.
  - **`DB002-03` · `Open`** — Add rollback/idempotency integration tests.
    - **Primary files:** tests/integration
    - **Acceptance:** A partial write does not leave inconsistent state.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `DB-003` — Separate initial, external, analyst, and effective assessments.

  **Work breakdown:**

  - **`DB003-01` · `Open`** — Define source-specific result models/columns.
    - **Primary files:** domain plus migrations
    - **Acceptance:** Every assessment source is stored separately.
  - **`DB003-02` · `Open`** — Implement a deterministic effective-result resolver.
    - **Primary files:** result service
    - **Acceptance:** Source priorities and provenance are explicit.
  - **`DB003-03` · `Open`** — Add regression coverage for recomputation after review/override.
    - **Primary files:** tests
    - **Acceptance:** Initial evidence is never overwritten.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `DB-004` — Add optimistic concurrency and an audit log.

  **Work breakdown:**

  - **`DB004-01` · `Open`** — Add version/revision columns and compare-and-swap writes.
    - **Primary files:** migrations/repositories
    - **Acceptance:** A stale update is rejected.
  - **`DB004-02` · `Open`** — Add append-only audit events.
    - **Primary files:** audit-log domain/repository
    - **Acceptance:** Actor, action, before/after, and reason are recorded.
  - **`DB004-03` · `Open`** — Add concurrent analyst/review tests.
    - **Primary files:** integration tests
    - **Acceptance:** Lost updates are impossible.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `HIST-001` — Retrieve the previous comparable result.

  **Work breakdown:**

  - **`HIST001-01` · `Open`** — Define the comparison key: client/asset/framework/requirement.
    - **Primary files:** history domain
    - **Acceptance:** Only compatible revisions are compared.
  - **`HIST001-02` · `Open`** — Add a repository query for the latest comparable result.
    - **Primary files:** history repository/service
    - **Acceptance:** Cancelled and incomplete runs are filtered out.
  - **`HIST001-03` · `Open`** — Add tests for missing or incompatible history.
    - **Primary files:** tests
    - **Acceptance:** No false comparison is produced.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `HIST-002` — Implement a deterministic change classifier.

  **Work breakdown:**

  - **`HIST002-01` · `Open`** — Define `new`/`resolved`/`regressed`/`unchanged`/`changed` states.
    - **Primary files:** history classifier
    - **Acceptance:** Rules do not depend on the LLM.
  - **`HIST002-02` · `Open`** — Compare status and normalized observations.
    - **Primary files:** classifier service
    - **Acceptance:** The order of observed items does not affect the result.
  - **`HIST002-03` · `Open`** — Add property and regression tests.
    - **Primary files:** tests
    - **Acceptance:** Classification is reproducible.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `EXC-001` — Create an approved-exception registry.

  **Work breakdown:**

  - **`EXC001-01` · `Open`** — Define the exception model: scope, owner, reason, expiry, and approval.
    - **Primary files:** domain plus migrations
    - **Acceptance:** An exception is not a free-form comment.
  - **`EXC001-02` · `Open`** — Add CRUD/service/API with authorization and audit logging.
    - **Primary files:** exception service/API
    - **Acceptance:** Every change requires an actor and reason.
  - **`EXC001-03` · `Open`** — Add expiry/revocation tests.
    - **Primary files:** tests
    - **Acceptance:** An expired exception is not applied.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `EXC-002` — Apply exceptions to observed items.

  **Work breakdown:**

  - **`EXC002-01` · `Open`** — Implement a deterministic exception-to-finding matcher.
    - **Primary files:** exception matcher
    - **Acceptance:** Scope matching is exact and fail-closed.
  - **`EXC002-02` · `Open`** — Preserve the original observation and applied-exception provenance.
    - **Primary files:** result service
    - **Acceptance:** The finding is not deleted.
  - **`EXC002-03` · `Open`** — Add tests for partial match, no match, and expiry.
    - **Primary files:** tests
    - **Acceptance:** Unrelated findings are not suppressed.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `HIST-003` — Include history and exceptions in the current assessment.

  **Work breakdown:**

  - **`HIST003-01` · `Open`** — Add comparable history and exceptions to assessment context.
    - **Primary files:** assessment context builder
    - **Acceptance:** Only scoped and pinned records are provided.
  - **`HIST003-02` · `Open`** — Add deterministic pre/post-processing around the LLM.
    - **Primary files:** assessment workflow
    - **Acceptance:** The LLM cannot change exception semantics.
  - **`HIST003-03` · `Open`** — Persist change classification and exception application.
    - **Primary files:** result repository
    - **Acceptance:** Reports can explain the current status.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `HIST-004` — Add repeated-audit E2E regression coverage.

  **Work breakdown:**

  - **`HIST004-01` · `Open`** — Create a synthetic first/second audit dataset.
    - **Primary files:** tests/fixtures/history
    - **Acceptance:** It contains resolved, regressed, and accepted-exception cases.
  - **`HIST004-02` · `Open`** — Run two audits and verify classifications.
    - **Primary files:** E2E tests
    - **Acceptance:** The previous result is found correctly.
  - **`HIST004-03` · `Open`** — Verify report/history persistence.
    - **Primary files:** reporting E2E
    - **Acceptance:** Results remain reproducible after restart.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

### M5 — Unified report generation

- [ ] `REPORT-001` — Create a separate reporting package.

  **Work breakdown:**

  - **`REPORT001-01` · `Open`** — Create a package boundary and public service API.
    - **Primary files:** `src/auditor/reporting/` (new)
    - **Acceptance:** Workflow code does not format reports inline.
  - **`REPORT001-02` · `Open`** — Define renderer interfaces.
    - **Primary files:** reporting interfaces
    - **Acceptance:** Markdown, Excel, and Word use one dataset.
  - **`REPORT001-03` · `Open`** — Remove or adapt legacy report call sites.
    - **Primary files:** graph/API/CLI
    - **Acceptance:** There is one reporting entry point.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-002` — Introduce versioned `ReportDataset`.

  **Work breakdown:**

  - **`REPORT002-01` · `Open`** — Define a strict versioned dataset schema.
    - **Primary files:** `src/auditor/reporting/domain.py`
    - **Acceptance:** Unknown fields and unsupported versions are rejected.
  - **`REPORT002-02` · `Open`** — Include identities, results, history, exceptions, and metrics.
    - **Primary files:** reporting domain
    - **Acceptance:** Every renderer receives sufficient structured data.
  - **`REPORT002-03` · `Open`** — Add JSON round-trip/schema tests.
    - **Primary files:** tests/reporting
    - **Acceptance:** The dataset is deterministic.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-003` — Build the dataset from structured sources.

  **Work breakdown:**

  - **`REPORT003-01` · `Open`** — Build the dataset from repositories/evidence/registries.
    - **Primary files:** reporting builder
    - **Acceptance:** Generated Markdown is never re-parsed as a source.
  - **`REPORT003-02` · `Open`** — Resolve effective result, history, and exceptions.
    - **Primary files:** builder services
    - **Acceptance:** Source provenance is preserved.
  - **`REPORT003-03` · `Open`** — Define missing/partial-data semantics.
    - **Primary files:** builder tests
    - **Acceptance:** An incomplete run is not reported as complete.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-004` — Add cross-record validation.

  **Work breakdown:**

  - **`REPORT004-01` · `Open`** — Validate foreign identities and uniqueness.
    - **Primary files:** reporting validator
    - **Acceptance:** No orphan results or jobs exist.
  - **`REPORT004-02` · `Open`** — Validate totals and status consistency.
    - **Primary files:** validator
    - **Acceptance:** Summary values match detailed records.
  - **`REPORT004-03` · `Open`** — Define fail/warn policy and tests.
    - **Primary files:** tests
    - **Acceptance:** A critical inconsistency blocks publication.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-005` — Implement one metrics engine.

  **Work breakdown:**

  - **`REPORT005-01` · `Open`** — Define canonical metric formulas.
    - **Primary files:** reporting metrics
    - **Acceptance:** Formulas are versioned.
  - **`REPORT005-02` · `Open`** — Calculate management/host/framework metrics from the dataset.
    - **Primary files:** metrics engine
    - **Acceptance:** Renderers do not recalculate metrics independently.
  - **`REPORT005-03` · `Open`** — Add golden tests for counts and percentages.
    - **Primary files:** tests
    - **Acceptance:** Markdown, Excel, and Word do not diverge.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-006` — Produce canonical `report.json` and checksum.

  **Work breakdown:**

  - **`REPORT006-01` · `Open`** — Serialize canonical sorted JSON.
    - **Primary files:** reporting serializer
    - **Acceptance:** The same dataset produces identical JSON.
  - **`REPORT006-02` · `Open`** — Calculate checksum and manifest.
    - **Primary files:** reporting publication
    - **Acceptance:** The checksum is pinned before rendering.
  - **`REPORT006-03` · `Open`** — Add integrity tests.
    - **Primary files:** tests
    - **Acceptance:** Artifact modification is detected.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-007` — Render Markdown from `ReportDataset`.

  **Work breakdown:**

  - **`REPORT007-01` · `Open`** — Implement a deterministic Markdown renderer.
    - **Primary files:** reporting Markdown module
    - **Acceptance:** The LLM does not rewrite immutable results.
  - **`REPORT007-02` · `Open`** — Add management summary and per-host tables.
    - **Primary files:** templates
    - **Acceptance:** Every finding and limitation is represented.
  - **`REPORT007-03` · `Open`** — Add golden-file tests.
    - **Primary files:** tests/golden
    - **Acceptance:** Output is stable.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-008` — Produce management Excel reports.

  **Work breakdown:**

  - **`REPORT008-01` · `Open`** — Define workbook layout: Management Summary, dashboard, and per-host results.
    - **Primary files:** reporting Excel module/template
    - **Acceptance:** One workbook covers every host.
  - **`REPORT008-02` · `Open`** — Build charts/KPIs from the metrics engine.
    - **Primary files:** Excel renderer
    - **Acceptance:** Charts use dataset values rather than manually supplied values.
  - **`REPORT008-03` · `Open`** — Add validation, formatting, freeze panes, and filtering usability.
    - **Primary files:** template/tests
    - **Acceptance:** The file opens without repair warnings.
  - **`REPORT008-04` · `Open`** — Add golden/structural tests.
    - **Primary files:** tests
    - **Acceptance:** Sheets, tables, formulas, and counts are verified.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-009` — Produce management Word reports.

  **Work breakdown:**

  - **`REPORT009-01` · `Open`** — Create a DOCX template and renderer.
    - **Primary files:** reporting DOCX module/template
    - **Acceptance:** Styles and sections are consistent.
  - **`REPORT009-02` · `Open`** — Generate management narrative only from structured fields.
    - **Primary files:** renderer
    - **Acceptance:** No fabricated data is introduced.
  - **`REPORT009-03` · `Open`** — Add document-structure regression tests.
    - **Primary files:** tests
    - **Acceptance:** Tables, headings, and links are correct.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-010` — Publish atomically with versioning.

  **Work breakdown:**

  - **`REPORT010-01` · `Open`** — Implement stage→validate→atomic-rename publication.
    - **Primary files:** reporting publisher
    - **Acceptance:** A partial file set is never published.
  - **`REPORT010-02` · `Open`** — Add version directory, manifest, and latest pointer.
    - **Primary files:** publisher
    - **Acceptance:** Previous reports are retained.
  - **`REPORT010-03` · `Open`** — Add crash/retry tests.
    - **Primary files:** tests
    - **Acceptance:** Repeated publication is idempotent.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-011` — Integrate reporting into every call site.

  **Work breakdown:**

  - **`REPORT011-01` · `Open`** — Make CLI/API/graph use the reporting service.
    - **Primary files:** call sites
    - **Acceptance:** No alternative renderer path remains.
  - **`REPORT011-02` · `Open`** — Define asynchronous status and error semantics.
    - **Primary files:** API/runtime
    - **Acceptance:** Publication state is reflected in run status.
  - **`REPORT011-03` · `Open`** — Clean up compatibility paths.
    - **Primary files:** legacy report modules
    - **Acceptance:** Old paths are removed or explicitly deprecated.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REPORT-012` — Add a complete reporting regression suite.

  **Work breakdown:**

  - **`REPORT012-01` · `Open`** — Create a synthetic dataset with edge cases.
    - **Primary files:** tests/fixtures/reporting
    - **Acceptance:** History, exceptions, partial, and unsupported cases are included.
  - **`REPORT012-02` · `Open`** — Add cross-format consistency tests.
    - **Primary files:** tests/reporting
    - **Acceptance:** Markdown, Excel, and Word have identical counts.
  - **`REPORT012-03` · `Open`** — Add artifact-integrity and reproducibility tests.
    - **Primary files:** tests
    - **Acceptance:** Checksums are stable.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

### M6 — Anonymization and external model review

- [ ] `REVIEW-001` — Introduce versioned `ReviewPackage`.

  **Work breakdown:**

  - **`REVIEW001-01` · `Open`** — Define a strict package schema and identity.
    - **Primary files:** review domain
    - **Acceptance:** The package is bound to report/result revisions.
  - **`REVIEW001-02` · `Open`** — Add manifest, checksum, and source references.
    - **Primary files:** review package builder
    - **Acceptance:** The package is reproducible.
  - **`REVIEW001-03` · `Open`** — Add schema and round-trip tests.
    - **Primary files:** tests/review
    - **Acceptance:** Unsupported versions are rejected.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-002` — Create a reversible anonymization map.

  **Work breakdown:**

  - **`REVIEW002-01` · `Open`** — Define tokenization rules for hosts/users/IPs/secrets/identifiers.
    - **Primary files:** anonymization module
    - **Acceptance:** Mapping is deterministic within the package.
  - **`REVIEW002-02` · `Open`** — Store the mapping with encryption and access control.
    - **Primary files:** review persistence
    - **Acceptance:** The map is never sent to the external model.
  - **`REVIEW002-03` · `Open`** — Add collision and round-trip tests.
    - **Primary files:** tests
    - **Acceptance:** De-anonymization is exact.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-003` — Detect leaks before sending.

  **Work breakdown:**

  - **`REVIEW003-01` · `Open`** — Add secret/PII/IP/domain scanners.
    - **Primary files:** leak detector
    - **Acceptance:** Known canaries are detected.
  - **`REVIEW003-02` · `Open`** — Add a fail-closed release gate.
    - **Primary files:** review service
    - **Acceptance:** A package containing a leak is not sent.
  - **`REVIEW003-03` · `Open`** — Add an audited false-positive allow mechanism.
    - **Primary files:** policy/tests
    - **Acceptance:** Every exception is explicit and logged.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-004` — Implement an external-model adapter.

  **Work breakdown:**

  - **`REVIEW004-01` · `Open`** — Define a provider-neutral interface and settings.
    - **Primary files:** external-model adapter
    - **Acceptance:** Provider secrets are resolved only at runtime.
  - **`REVIEW004-02` · `Open`** — Add timeout/retry/rate-limit/cost metadata.
    - **Primary files:** adapter runtime
    - **Acceptance:** Errors are typed.
  - **`REVIEW004-03` · `Open`** — Add mock-provider tests.
    - **Primary files:** tests
    - **Acceptance:** Unit tests require no network access.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-005` — Validate external-model responses.

  **Work breakdown:**

  - **`REVIEW005-01` · `Open`** — Define a structured response schema.
    - **Primary files:** review domain
    - **Acceptance:** Free-form prose cannot modify results.
  - **`REVIEW005-02` · `Open`** — Validate referenced IDs and allowed changes.
    - **Primary files:** review validator
    - **Acceptance:** Unknown or missing IDs are rejected.
  - **`REVIEW005-03` · `Open`** — Add adversarial and malformed-response tests.
    - **Primary files:** tests
    - **Acceptance:** Prompt injection cannot expand scope.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-006` — Perform atomic de-anonymization.

  **Work breakdown:**

  - **`REVIEW006-01` · `Open`** — Validate the complete mapping before replacement.
    - **Primary files:** de-anonymizer
    - **Acceptance:** A partial mapping blocks the operation.
  - **`REVIEW006-02` · `Open`** — Create output atomically.
    - **Primary files:** review service
    - **Acceptance:** No partially de-anonymized artifact is produced.
  - **`REVIEW006-03` · `Open`** — Add round-trip tests.
    - **Primary files:** tests
    - **Acceptance:** Original identifiers are restored exactly.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-007` — Persist reviews and recalculate effective results.

  **Work breakdown:**

  - **`REVIEW007-01` · `Open`** — Persist immutable external review data.
    - **Primary files:** DB/repository
    - **Acceptance:** The initial result remains unchanged.
  - **`REVIEW007-02` · `Open`** — Recompute effective results using source priorities.
    - **Primary files:** result service
    - **Acceptance:** External changes are traceable.
  - **`REVIEW007-03` · `Open`** — Add audit-log and idempotency tests.
    - **Primary files:** tests
    - **Acceptance:** Repeated import is idempotent.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-008` — Define error and publication semantics.

  **Work breakdown:**

  - **`REVIEW008-01` · `Open`** — Define typed lifecycle statuses: queued/sent/received/validated/rejected/published.
    - **Primary files:** review domain/service
    - **Acceptance:** Status transitions are valid.
  - **`REVIEW008-02` · `Open`** — Define retry and terminal-error policy.
    - **Primary files:** review runtime
    - **Acceptance:** Duplicate publication is impossible.
  - **`REVIEW008-03` · `Open`** — Add operator-visible API errors.
    - **Primary files:** API/docs/tests
    - **Acceptance:** Errors contain no secrets.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `REVIEW-009` — Test the complete external-review path.

  **Work breakdown:**

  - **`REVIEW009-01` · `Open`** — Add a build→anonymize→scan→send→validate→deanonymize→persist fixture.
    - **Primary files:** E2E tests
    - **Acceptance:** Every stage is covered.
  - **`REVIEW009-02` · `Open`** — Inject failures at every stage.
    - **Primary files:** E2E tests
    - **Acceptance:** Atomicity is preserved.
  - **`REVIEW009-03` · `Open`** — Verify report regeneration.
    - **Primary files:** report/review E2E
    - **Acceptance:** Effective results are reflected exactly once.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

### M7 — Analyst edits and regeneration

- [ ] `ANALYST-001` — Deterministically import reviewed Excel workbooks.

  **Work breakdown:**

  - **`ANALYST001-01` · `Open`** — Define editable cells, row identity, and template version.
    - **Primary files:** analyst import domain
    - **Acceptance:** Immutable columns are protected.
  - **`ANALYST001-02` · `Open`** — Parse the workbook without formula ambiguity.
    - **Primary files:** import service
    - **Acceptance:** Rows map to canonical result IDs.
  - **`ANALYST001-03` · `Open`** — Produce a validation/error report.
    - **Primary files:** tests
    - **Acceptance:** An invalid workbook is never partially applied.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `ANALYST-002` — Add transactional overrides and report versions.

  **Work breakdown:**

  - **`ANALYST002-01` · `Open`** — Persist analyst overrides separately.
    - **Primary files:** DB/domain
    - **Acceptance:** Original and external results remain unchanged.
  - **`ANALYST002-02` · `Open`** — Apply all workbook changes in one transaction.
    - **Primary files:** repository/service
    - **Acceptance:** Any failure rolls back all changes.
  - **`ANALYST002-03` · `Open`** — Create a new effective-result/report revision.
    - **Primary files:** report service
    - **Acceptance:** The previous version is retained.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `ANALYST-003` — Expose explicit service/CLI/API operations.

  **Work breakdown:**

  - **`ANALYST003-01` · `Open`** — Add service commands for validate/import/preview/apply/regenerate.
    - **Primary files:** analyst service
    - **Acceptance:** API code does not access repositories directly.
  - **`ANALYST003-02` · `Open`** — Add CLI/API endpoints with actor and reason.
    - **Primary files:** CLI/API
    - **Acceptance:** Mutations are audited.
  - **`ANALYST003-03` · `Open`** — Add authorization and idempotency tests.
    - **Primary files:** tests
    - **Acceptance:** Repeated apply operations are safe.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `ANALYST-004` — Add import/regeneration round-trip tests.

  **Work breakdown:**

  - **`ANALYST004-01` · `Open`** — Generate a workbook from a synthetic dataset.
    - **Primary files:** E2E fixture
    - **Acceptance:** Editable cells are known and versioned.
  - **`ANALYST004-02` · `Open`** — Modify, import, and regenerate every report format.
    - **Primary files:** E2E tests
    - **Acceptance:** Overrides are reflected consistently.
  - **`ANALYST004-03` · `Open`** — Verify history, audit log, and version preservation.
    - **Primary files:** tests
    - **Acceptance:** No source data is lost.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

### M8 — Observability, cleanup, and release gate

- [ ] `OPS-001` — Introduce a typed error taxonomy.

  **Work breakdown:**

  - **`OPS001-01` · `Open`** — Define domain error codes, categories, and retryability.
    - **Primary files:** `src/auditor/domain/errors.py` (new)
    - **Acceptance:** Control flow does not depend on string matching.
  - **`OPS001-02` · `Open`** — Map adapters, workflows, and API errors to the taxonomy.
    - **Primary files:** runtime/API modules
    - **Acceptance:** HTTP and CLI semantics are consistent.
  - **`OPS001-03` · `Open`** — Add contract tests and secret-safe messages.
    - **Primary files:** tests
    - **Acceptance:** Errors contain identities, not secrets.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `OPS-002` — Add structured logs, metrics, and a run manifest.

  **Work breakdown:**

  - **`OPS002-01` · `Open`** — Define a structured log schema with correlation IDs.
    - **Primary files:** logging config/runtime
    - **Acceptance:** Client, run, job, and tool IDs are present.
  - **`OPS002-02` · `Open`** — Add lifecycle, tool, error, latency, and retry metrics.
    - **Primary files:** metrics module
    - **Acceptance:** Labels are bounded and contain no secrets.
  - **`OPS002-03` · `Open`** — Persist a run manifest with pinned identities and configuration.
    - **Primary files:** run manifest module
    - **Acceptance:** Execution is reproducible and auditable.
  - **`OPS002-04` · `Open`** — Add observability tests.
    - **Primary files:** tests
    - **Acceptance:** Required fields are emitted.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `OPS-003` — Remove legacy Markdown parsing from production flow.

  **Work breakdown:**

  - **`OPS003-01` · `Open`** — Identify production reads of generated Markdown.
    - **Primary files:** code search/architecture document
    - **Acceptance:** The list of call sites is fixed and documented.
  - **`OPS003-02` · `Open`** — Replace them with structured repositories/datasets.
    - **Primary files:** workflow/report modules
    - **Acceptance:** Markdown remains only a presentation format or framework source where intended.
  - **`OPS003-03` · `Open`** — Delete compatibility parsers after migration.
    - **Primary files:** legacy modules/tests
    - **Acceptance:** No hidden production dependency remains.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [~] `OPS-004` — Perform modular cleanup and dependency review.

  **Work breakdown:**

  - **`OPS004-01` · `Partial`** — Split large inventory/tool/workflow modules.
    - **Primary files:** `src/auditor/inventory/`, tools/workflows
    - **Acceptance:** Public boundaries are documented.
  - **`OPS004-02` · `Open`** — Remove dead/deprecated paths and duplicate helpers.
    - **Primary files:** repository-wide
    - **Acceptance:** No unused fallback implementation remains.
  - **`OPS004-03` · `Open`** — Review dependency pins, licenses, and security.
    - **Primary files:** `pyproject.toml`, lock file, docs
    - **Acceptance:** Unused dependencies are removed and risky versions are addressed.
  - **`OPS004-04` · `Open`** — Add import-cycle, module-size, and static checks.
    - **Primary files:** CI/scripts
    - **Acceptance:** Architecture regressions are detected.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [~] `DOC-001` — Update user and developer documentation.

  **Work breakdown:**

  - **`DOC001-01` · `Partial`** — Document the inventory/framework/tool-registry/preflight lifecycle.
    - **Primary files:** `README.md`, `docs/architecture.md`, `docs/tools.md`
    - **Acceptance:** Documentation reflects the current POC.
  - **`DOC001-02` · `Open`** — Document the work-item checklist and task-specification process.
    - **Primary files:** `checklist/README.md` (new), contribution docs
    - **Acceptance:** Any child ID can be delivered in a separate PR.
  - **`DOC001-03` · `Open`** — Synchronize EN/RU documentation and CI counters.
    - **Primary files:** `checklist/*.md`, docs
    - **Acceptance:** Statuses and counts do not diverge.
  - **`DOC001-04` · `Open`** — Add operator runbooks for analyze/confirm/start/stale/errors.
    - **Primary files:** `docs/runbooks/` (new)
    - **Acceptance:** API and CLI examples are current.

  **Parent status rule:** keep `[~]` until all mandatory work items are complete and independent acceptance has been performed.

- [ ] `DOC-002` — Provide a fully synthetic sample package.

  **Work breakdown:**

  - **`DOC002-01` · `Open`** — Add synthetic inventory, credential references, frameworks, and evidence.
    - **Primary files:** `examples/sample_client/` (new)
    - **Acceptance:** No real client data is included.
  - **`DOC002-02` · `Open`** — Add expected plans, results, and reports.
    - **Primary files:** examples/golden
    - **Acceptance:** The demo is reproducible offline with fake adapters.
  - **`DOC002-03` · `Open`** — Validate the quickstart in CI.
    - **Primary files:** CI/example tests
    - **Acceptance:** The sample does not become stale.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `CI-001` — Implement a complete release pipeline.

  **Work breakdown:**

  - **`CI001-01` · `Open`** — Add migration, unit, integration, and E2E matrices.
    - **Primary files:** `.github/workflows/release.yml` (new)
    - **Acceptance:** Release is blocked by any failed mandatory suite.
  - **`CI001-02` · `Open`** — Build/package, generate SBOM, and scan vulnerabilities.
    - **Primary files:** CI scripts
    - **Acceptance:** Artifacts are reproducible and scanned.
  - **`CI001-03` · `Open`** — Publish signed/checksummed artifacts.
    - **Primary files:** release workflow
    - **Acceptance:** Provenance is available.
  - **`CI001-04` · `Open`** — Define release checklist, version, and tag rules.
    - **Primary files:** docs/scripts
    - **Acceptance:** No undocumented manual release path exists.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

- [ ] `E2E-001` — Implement the final acceptance scenario.

  **Work breakdown:**

  - **`E2E001-01` · `Open`** — Create synthetic multi-client/multi-host inventory and tools.
    - **Primary files:** E2E fixtures
    - **Acceptance:** Linux, Windows, PostgreSQL, Cisco, and unsupported assets are included.
  - **`E2E001-02` · `Open`** — Cover analyze→discovery→confirm→execute→history/exceptions→reports.
    - **Primary files:** E2E suite
    - **Acceptance:** The lifecycle completes with canonical identities.
  - **`E2E001-03` · `Open`** — Cover external review, analyst override, and regeneration.
    - **Primary files:** E2E suite
    - **Acceptance:** Effective-result and report revisions are correct.
  - **`E2E001-04` · `Open`** — Cover failure, resume, cancel, stale, and security scenarios.
    - **Primary files:** E2E suite
    - **Acceptance:** Fail-closed behavior is verified.
  - **`E2E001-05` · `Open`** — Produce independent release-acceptance evidence.
    - **Primary files:** checklist/release artifacts
    - **Acceptance:** Every mandatory parent requirement is accepted.

  **Parent status rule:** keep `[ ]` until meaningful implementation exists; change to `[~]` or `[x]` only after independent review.

## Current blockers and nearest sequence

1. `INPUT005-07` — pin the exact `plan_revision_id` during confirm/start.
2. `INPUT005-09` + `INPUT005-10` + `INPUT005-11` — metadata, predicates, and the normalized fact namespace.
3. `INPUT005-12` + `INPUT005-13` — dynamic framework selection without hardcoded mapping.
4. `INPUT005-14` + `INPUT005-18` + `INPUT005-19` — discovery plan, provenance, and operator clarification.
5. `TOOL-003` + `TOOL-004` + `TOOL-005` — HTTP, TCP, and SNMP adapters.
6. `FLOW-001` + `FLOW-003` + `FLOW-004` — typed graph foundation and requirement worker.
7. `FLOW-002` + `FLOW-005` + `FLOW-006` — `Send`, resilience, resume, and cancellation.
8. `AGENT-001` — governed LLM runtime.
9. `E2E-001` — final product acceptance.

Recommended split for the next pull requests:

```text
PR A: INPUT005-07
PR B: INPUT005-09 + INPUT005-10 + INPUT005-11
PR C: INPUT005-12 + INPUT005-13
PR D: INPUT005-14 + INPUT005-18 + INPUT005-19
PR E: TOOL-004 + INPUT005-15
PR F: TOOL-003 + INPUT005-16
PR G: TOOL-005 + INPUT005-17
PR H: INPUT005-20 + INPUT005-21 + INPUT005-22
```

## Status rules

- `[ ]` Open: independent acceptance has not been confirmed.
- `[~]` Partial: meaningful implementation exists, but not all acceptance criteria are complete.
- `[x]` Accepted: every criterion is supported by code, tests, and independent review.
- `Done/Partial/Open/Blocked/Backlog` apply only to child work items.
- Green CI alone does not move a parent requirement to `[x]`.
- When a new problem is found, create a child work item under the corresponding parent; do not expand the top-level list of 77 requirements without a separate architecture decision.

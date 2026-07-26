# Defect → module map (AUD-001)

Canonical mapping of every checklist defect/task ID to production ownership.

| Field | Value |
|-------|-------|
| Reviewed commit SHA | `d55ac3adae94538a0bc79c2b20582a3bb6769f4d` |
| Checklist source | [`checklist/psql_auditor_master_refactoring_checklist (5).md`](../checklist/psql_auditor_master_refactoring_checklist%20(5).md) (version **1.7**, dated 2026-07-26) |
| Validation | `make validate-defect-map` (`scripts/validate_defect_map.py`) |

## Status legend

| Status | Meaning |
|--------|---------|
| `IMPLEMENTED — DEFECT PRESENT` | Capability exists in production code but violates acceptance criteria |
| `PARTIALLY IMPLEMENTED` | Scaffolding or incomplete implementation exists |
| `MODULE NOT IMPLEMENTED` | Required capability/module is absent |
| `LOCATION NOT CONFIRMED` | Ownership could not be established reliably |
| `RESOLVED` | Fix supported by current code **and** tests |

Paths are repository-relative. Rows with status `MODULE NOT IMPLEMENTED` use `— (capability absent)` when no module exists.

## Map

| Defect ID | Production module(s) | Main callable/class | Implementation status | Evidence/notes |
| --------- | -------------------- | ------------------- | --------------------- | -------------- |

| AUD-001 | `docs/baseline.md`, `docs/defect-module-map.md`, `scripts/validate_defect_map.py` | `validate_defect_map`, `make validate-defect-map` | RESOLVED | Complete checklist→module map with automated validator and gate tests; reviewed on HEAD with checklist v1.7. |
| AUD-002 | `Makefile`, `scripts/run_pytest_group.py`, `.github/workflows/ci.yml`, `src/auditor/testing/fake_llm.py` | `make check`, `run_pytest_group.main`, `DeterministicFakeChatModel` | RESOLVED | Unified local/CI gates green; zero-discovery fails; isolated PG + LLM fake; tests in `tests/gates/`. |
| AUD-003 | `src/auditor/testing/fake_llm.py`, `tests/conftest.py`, `tests/integration/conftest.py` | `DeterministicFakeChatModel`, `isolated_results_db` | PARTIALLY IMPLEMENTED | Fake LLM + PG isolation fixtures exist; no shared deterministic fixture package covering SSH/MCP/inventory. |
| CORE-001 | `src/auditor/client_registry.py`, `src/auditor/legacy_compat.py`, `src/auditor/evidence_store.py`, `src/auditor/results_store.py`, `src/auditor/workflows/intake.py`, `src/auditor/workflows/runner.py` | `ClientRegistry`, `require_audit_run_id`, `EvidenceStore.write_finding`, `ResultsStore.start_session` | PARTIALLY IMPLEMENTED | Nested evidence layout + required `audit_run_id` on session start/write_finding; some warehouse update paths still tolerate empty `client_id` (checklist blocker). Tests: `tests/test_client_audit_run_identity.py`. |
| CORE-002 | `src/auditor/domain/audit_models.py`, `src/auditor/audit_registry.py`, `src/auditor/workflows/multi_runner.py` | `AuditRun`, `AuditJob`, `AuditRegistry` | RESOLVED | Separate run/job models with registry transitions; tests: `tests/test_audit_run_job.py`. |
| CORE-003 | `src/auditor/domain/result_identity.py`, `src/auditor/result_identity_bind.py`, `src/auditor/state.py`, `src/auditor/evidence_store.py`, `src/auditor/results_store.py` | `validate_result_identity`, `merge_result_maps`, `merge_findings` | RESOLVED | Canonical `result_id` + logical key enforced on persist/merge; tests: `tests/test_canonical_result_identity.py`. |
| CORE-004 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No `AssessmentResult` type; assessments use `Finding` in `src/auditor/state.py`. |
| CORE-005 | `src/auditor/workflows/runner.py`, `src/auditor/config.py`, `src/auditor/graph.py` | `ensure_async_checkpointer`, `Settings.checkpoint_path` | IMPLEMENTED — DEFECT PRESENT | Durable Sqlite checkpointer is process-wide via `checkpoint_path`; not isolated per `audit_run_id`. |
| CORE-006 | `src/auditor/graph.py`, `src/auditor/config.py`, `src/auditor/evidence_store.py`, `src/auditor/runtime_target.py` | `get_auditor_graph`, `get_settings`, `bind_runtime_credentials` | PARTIALLY IMPLEMENTED | ContextVar host/runtime binds exist; process singletons (`_graph`, settings cache, evidence maps) remain. |
| INPUT-001 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No strict `AuditRequest` pydantic/dataclass validator under `src/`. |
| INPUT-002 | `src/auditor/frameworks.py`, `src/auditor/checklist.py` | `load_framework_checklist`, `parse_checklist_markdown`, `route_framework` | IMPLEMENTED — DEFECT PRESENT | Frameworks loaded from Markdown/YAML frontmatter without a hard schema reject path for invalid agents. |
| INPUT-003 | `src/auditor/secrets_file.py`, `src/auditor/asset_registry.py`, `src/auditor/host_facts.py` | `read_client_credentials`, `InventorySshTarget`, `AssetRegistry.ensure_asset` | PARTIALLY IMPLEMENTED | Ad-hoc inventory/SSH tables and `HostFacts`; no validated inventory domain model. |
| INPUT-004 | `src/auditor/mcp_registry.py`, `src/auditor/graph.py`, `src/auditor/tools/mcp_client.py`, `src/auditor/tools/ssh.py` | `load_mcp_registry`, `_all_tools` | PARTIALLY IMPLEMENTED | MCP registry + LangChain tool binding exist; no unified capability/read-only policy registry. |
| INPUT-005 | `src/auditor/intake.py`, `src/auditor/access_probe.py`, `src/auditor/workflows/intake.py` | `parse_audit_plan_markdown`, `intake_gate` | PARTIALLY IMPLEMENTED | Markdown PLAN parsing and access probes exist; no typed `AuditPlan` / deterministic preflight service. |
| FLOW-001 | `src/auditor/state.py`, `src/auditor/workflows/builder.py` | `AuditorState`, `build_main_graph` | IMPLEMENTED — DEFECT PRESENT | TypedDict state wired into LangGraph but carries many optional intake/archive/HITL fields (not minimal). |
| FLOW-002 | `src/auditor/workflows/assessment.py`, `src/auditor/workflows/tool_execution.py`, `src/auditor/workflows/multi_runner.py` | `assess_parallel`, `execute_tool_calls` | IMPLEMENTED — DEFECT PRESENT | Parallelism uses `asyncio.gather`; no LangGraph `Send` fan-out under `src/`. |
| FLOW-003 | `src/auditor/state.py`, `src/auditor/domain/result_identity.py` | `merge_findings`, `merge_result_maps` | PARTIALLY IMPLEMENTED | Conflict-aware reducer exists (CORE-003); overwrite/legacy-key edge cases remain vs lossless requirements. |
| FLOW-004 | `src/auditor/workflows/assessment.py`, `src/auditor/workflows/builder.py` | `assess_parallel`, `build_main_graph` | IMPLEMENTED — DEFECT PRESENT | Requirement work runs inside main-graph `assess_parallel`, not a dedicated worker subgraph. |
| FLOW-005 | `src/auditor/workflows/assessment.py`, `src/auditor/config.py`, `src/auditor/tools/ssh.py` | `assess_parallel`, `Settings.max_parallel_assessments` | PARTIALLY IMPLEMENTED | Semaphores and SSH timeouts exist; no graph-level timeout/retry/backpressure policy. |
| FLOW-006 | `src/auditor/workflows/runner.py`, `src/auditor/api/openai_compat.py`, `src/auditor/hitl.py` | `aresume`, `acontinue`, `_run_or_resume` | PARTIALLY IMPLEMENTED | Checkpoint/HITL resume exists; cancellation is best-effort without full cancel semantics. |
| FLOW-007 | `src/auditor/graph.py`, `src/auditor/api/openai_compat.py` | `get_auditor_graph`, `get_auditor_graph_ready` | PARTIALLY IMPLEMENTED | Process-wide `_graph` singleton still used by API entry points. |
| EVID-001 | `src/auditor/evidence_store.py`, `src/auditor/workflows/tool_execution.py` | `EvidenceStore.write_tool_result` | PARTIALLY IMPLEMENTED | Tool sidecars store ad-hoc `{tool, arguments, result}`; no normalized evidence-item schema. |
| EVID-002 | `src/auditor/tools/postgres.py`, `src/auditor/tools/mcp_client.py`, `src/auditor/tools/ssh.py` | `is_readonly_sql`, `mcp_query` | PARTIALLY IMPLEMENTED | Read-only SQL gate for Postgres MCP; SSH/WinRM lack equivalent safe-invocation policy. |
| EVID-003 | `src/auditor/evidence_store.py` | `EvidenceStore.write_tool_result`, `write_finding` | IMPLEMENTED — DEFECT PRESENT | Sidecars include tool/seq/time but lack full provenance to run/asset/requirement/source. |
| EVID-004 | `src/auditor/workflows/helpers.py`, `src/auditor/workflows/assessment.py` | `_extract_json`, `cells_to_finding` | IMPLEMENTED — DEFECT PRESENT | Fill path parses free-text LLM JSON via regex, not structured-output binding. |
| EVID-005 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No evidence sufficiency/confidence types or evaluators under `src/`. |
| EVID-006 | `src/auditor/workflows/assessment.py`, `src/auditor/state.py`, `src/auditor/checklist.py` | `cells_to_finding`, `render_report`, `Requirement` | PARTIALLY IMPLEMENTED | Fixed checklist fields copied at fill/render; no enforcement preventing mutation elsewhere. |
| EVID-007 | `src/auditor/context.py`, `src/auditor/workflows/tool_execution.py`, `src/auditor/evidence_store.py` | `truncate_text`, `load_evidence_text` | IMPLEMENTED — DEFECT PRESENT | LLM-facing tool/evidence text is truncated before assessment/refill. |
| DB-001 | `migrations/001_audit_run_job.sql`, `migrations/002_canonical_result_identity.sql`, `migrations/003_client_audit_run_separation.sql`, `src/auditor/results_store.py`, `src/auditor/audit_registry.py`, `src/auditor/client_registry.py` | `ResultsStore._ensure_schema`, `AuditRegistry._ensure_schema` | PARTIALLY IMPLEMENTED | SQL files are documentation mirrors; schema applied inline on connect, no versioned migration runner. |
| DB-002 | `src/auditor/results_store.py` | `ResultsStore.record_host_framework_audit`, `upsert_requirement_result` | PARTIALLY IMPLEMENTED | `asyncpg` transactions exist inside a monolithic store; no repository/UoW boundary. |
| DB-003 | — (capability absent) | — | MODULE NOT IMPLEMENTED | Single `requirement_results` cell model; no initial/external/analyst/effective assessment layers. |
| DB-004 | `src/auditor/results_store.py`, `src/auditor/domain/result_identity.py` | `_upsert_requirement_cell`, `validate_result_identity` | PARTIALLY IMPLEMENTED | Identity conflict checks exist; no row_version/optimistic concurrency or audit_log table. |
| HIST-001 | `src/auditor/results_store.py` | `list_host_framework_results`, `list_session_requirement_results` | PARTIALLY IMPLEMENTED | Can load newest host/framework or session cells; no predecessor comparable-result API. |
| HIST-002 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No deterministic change-classifier module under `src/`. |
| EXC-001 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No approved-exception registry module or table. |
| EXC-002 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No exception-application logic on structured observed items. |
| HIST-003 | — (capability absent) | — | MODULE NOT IMPLEMENTED | `assess_parallel` has no history/exception inputs; capability absent. |
| HIST-004 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No repeat-audit orchestration path in production (tests alone are not the module). |
| REPORT-001 | `src/auditor/state.py`, `src/auditor/report_exports.py`, `src/auditor/compliance.py`, `src/auditor/report_archive.py`, `src/auditor/evidence_store.py` | `render_report`, `write_report_exports`, `package_and_publish_archive` | PARTIALLY IMPLEMENTED | Reporting logic spread across flat modules; no `src/auditor/reporting/` package. |
| REPORT-002 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No versioned `ReportDataset` type under `src/`. |
| REPORT-003 | `src/auditor/evidence_store.py`, `src/auditor/followup.py`, `src/auditor/workflows/finalize.py` | `load_findings`, `run_update_report`, `finalize` | PARTIALLY IMPLEMENTED | Findings loaded into `render_report`; no structured dataset builder. |
| REPORT-004 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No cross-record report validation layer. |
| REPORT-005 | `src/auditor/compliance.py`, `src/auditor/state.py`, `src/auditor/report_exports.py` | `findings_to_compliance_metrics`, `aggregate_findings`, `parse_report_rows` | IMPLEMENTED — DEFECT PRESENT | Duplicate metrics engines: Finding aggregates vs Markdown re-parse paths. |
| REPORT-006 | — (capability absent) | — | MODULE NOT IMPLEMENTED | Artifacts are `report.md` (+docx/xlsx); no canonical `report.json`/checksum. |
| REPORT-007 | `src/auditor/state.py` | `render_report` | PARTIALLY IMPLEMENTED | Markdown from Finding/Requirement maps, not from `ReportDataset`. |
| REPORT-008 | `src/auditor/report_exports.py`, `src/auditor/evidence_store.py` | `write_xlsx_report`, `write_report_exports` | PARTIALLY IMPLEMENTED | Excel built by parsing Markdown summary table. |
| REPORT-009 | `src/auditor/report_exports.py`, `src/auditor/evidence_store.py` | `write_docx_report`, `write_report_exports` | PARTIALLY IMPLEMENTED | Word export uses the same Markdown-parse path. |
| REPORT-010 | `src/auditor/report_archive.py` | `package_and_publish_archive`, `create_run_archive` | PARTIALLY IMPLEMENTED | ZIP + `archive.json` metadata; no atomic report versioning contract. |
| REPORT-011 | `src/auditor/workflows/finalize.py`, `src/auditor/followup.py`, `src/auditor/workflows/multi_runner.py`, `src/auditor/evidence_store.py` | `finalize`, `run_update_report`, `merge_multi_reports` | PARTIALLY IMPLEMENTED | Ad-hoc call sites; no unified reporting service integration. |
| REPORT-012 | `src/auditor/report_exports.py`, `src/auditor/compliance.py`, `src/auditor/state.py` | `write_report_exports`, `render_report` | PARTIALLY IMPLEMENTED | Unit coverage in `tests/test_report_exports.py` / `tests/test_compliance.py`; no complete reporting regression suite. |
| REVIEW-001 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No versioned `ReviewPackage` type. |
| REVIEW-002 | `src/auditor/anonymization.py`, `src/auditor/followup.py` | `ReversibleAnonymizer`, `write_mapping_file`, `run_anonymize_report` | PARTIALLY IMPLEMENTED | Reversible map + directory anonymize exist (`tests/test_anonymization.py` green); not a full ReviewPackage workflow. |
| REVIEW-003 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No leak-detection pass before external send. |
| REVIEW-004 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No external-review model adapter (`llm.py` is generic chat factory only). |
| REVIEW-005 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No external-model review response validator. |
| REVIEW-006 | `src/auditor/anonymization.py` | `ReversibleAnonymizer.deanonymize_text` | PARTIALLY IMPLEMENTED | String token restore only; no atomic de-anonymize workflow for review payloads. |
| REVIEW-007 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No persist-external-review + recompute-effective pipeline. |
| REVIEW-008 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No review failure/publication semantics module. |
| REVIEW-009 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No complete external-review production path (anonymize-copy only). |
| ANALYST-001 | — (capability absent) | — | MODULE NOT IMPLEMENTED | `report_exports.py` writes xlsx only; no reviewed-Excel import path. |
| ANALYST-002 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No transactional analyst-override storage or report versioning. |
| ANALYST-003 | `src/auditor/followup.py`, `src/auditor/intent.py`, `src/auditor/api/openai_compat.py`, `src/auditor/graph.py` | `run_update_report`, `classify_intent` | PARTIALLY IMPLEMENTED | Chat follow-up update/anonymize routes exist; no analyst import/regeneration CLI/API. |
| ANALYST-004 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No import/regeneration round-trip capability or owning module. |
| OPS-001 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No typed error taxonomy module; ad-hoc exceptions/`JobErrorInfo.error_type` strings only. |
| OPS-002 | `src/auditor/progress.py`, `src/auditor/evidence_store.py`, `src/auditor/api/stream_progress.py` | `ProgressEvent`, `emit_progress`, `write_run_meta` | PARTIALLY IMPLEMENTED | SSE progress + `meta.json`; no structured JSON logs/metrics/run-manifest contract. |
| OPS-003 | `src/auditor/report_exports.py`, `src/auditor/compliance.py`, `src/auditor/intake.py`, `src/auditor/workflows/finalize.py` | `parse_report_rows`, `parse_audit_plan_markdown`, `write_report_exports` | IMPLEMENTED — DEFECT PRESENT | Production still re-parses Markdown for exports, charts, plans, and multi-merge. |
| OPS-004 | `src/auditor/workflows/`, `src/auditor/graph.py`, `src/auditor/legacy_compat.py`, `src/auditor/workflows/dependencies.py` | `GraphDependencies`, `AuditorGraph`, `iter_evidence_roots` | PARTIALLY IMPLEMENTED | Workflows package extracted; façade/singleton/legacy paths remain; no completed dependency-review artifact. |
| DOC-001 | `docs/baseline.md`, `docs/quality-gates.md`, `docs/README.md`, `docs/pre-audit-intake.md`, `docs/adhoc-commands.md` | (documentation deliverables) | PARTIALLY IMPLEMENTED | `quality-gates.md` synced to AUD-002; `baseline.md` still mixes CORE-000 tables; some docs still show stale evidence layouts. |
| DOC-002 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No fully synthetic sample package directory in the repository. |
| CI-001 | `.github/workflows/ci.yml`, `Makefile`, `scripts/run_pytest_group.py` | `make check`, CI jobs `format-check`…`full-suite` | PARTIALLY IMPLEMENTED | Mandatory quality gates green (AUD-002); release E2E/migration coverage still missing per checklist blocker. |
| E2E-001 | — (capability absent) | — | MODULE NOT IMPLEMENTED | No final-acceptance E2E harness owner; `scripts/owui_*_test.py` are manual helpers only. |

## Notes

- This map does **not** change checklist checkbox statuses; those remain owned by acceptance review.
- Historical CORE-000 BASE-* test-failure IDs in older `docs/baseline.md` tables are not checklist defects and are out of scope for this map.
- Newly discovered issues found during inspection are reported in the AUD-001 closure report, not added here.


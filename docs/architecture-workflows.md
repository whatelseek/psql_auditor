# Workflow architecture (LangGraph orchestration)

## Baseline (CORE-000)

Reproducible install, verification commands, entry-point / storage / defect
maps, and measured gate results live in **[`baseline.md`](baseline.md)**.
Known failing pytest node IDs: [`baseline-failures.txt`](baseline-failures.txt).

## Purpose

`src/auditor/graph.py` is a **façade**: it constructs dependencies, compiles
LangGraph workflows, and exposes the public `AuditorGraph` API. Node logic,
scheduling, and lifecycle live under `src/auditor/workflows/`.

## Dependency direction

```text
graph.py  →  workflows/*  →  domain services (intake, hitl, tools, stores, …)
```

Workflow modules **must not** import `auditor.graph`. They type against
`workflows.protocols.AuditRuntime`, implemented by `AuditorGraph`.

## Module responsibilities

| Module | Owns |
|--------|------|
| `dependencies.py` | `GraphDependencies`, `EvidenceRegistry`, `MultiSessionRegistry` |
| `helpers.py` | Pure transforms (`_normalize_status`, `_hitl_candidates`, …) |
| `builder.py` | Main + intake `StateGraph` topology and compile |
| `intake.py` | `intake_gate` and intake LLM resolve helpers |
| `discovery.py` | `route_framework`, `load_framework`, `collect_host_facts` |
| `assessment.py` | `assess_parallel`, reconnect, fill/gather orchestration |
| `tool_execution.py` | Parallel tool calls + progress emit |
| `hitl.py` | `human_gate`, `route_after_assess`, `route_after_hitl` |
| `finalize.py` | `finalize` report/persistence |
| `runner.py` | `arun_one`, `aresume`, `acontinue`, `arun_intake`, checkpointer upgrade |
| `multi_runner.py` | Multi-host scheduling, host locks, merge, `arun` |

## Frozen compatibility contracts

Do **not** rename without a checkpoint migration:

- Nodes: `route_framework`, `load_framework`, `collect_host_facts`,
  `assess_parallel`, `reconnect_session`, `human_gate`, `finalize`, `intake_gate`
- Routers: `route_after_assess` → `{reconnect_session, human_gate, finalize}`;
  `route_after_hitl` → `{assess_parallel, human_gate, finalize}`
- Public API: `arun`, `arun_one`, `arun_intake`, `aresume`, `acontinue`, listing helpers
- HITL interrupt payload: `type=skip_or_retry`
- Intake interrupt payload: `type=intake`
- Helpers re-exported from `auditor.graph` for existing tests

## Run-scoped state

| Concern | Mechanism |
|---------|-----------|
| SSH/PG credentials | `runtime_target` ContextVar via `_target_scope` |
| Evidence stores | `EvidenceRegistry` / `_evidence_by_run` keyed by `run_id` |
| Multi-framework sessions | `MultiSessionRegistry` + `session_store` on disk |
| Checkpoints | process-level AsyncSqliteSaver on the façade |

## Baseline tests (recorded at refactor)

- Before/after: **197 passed, 11 failed** (pre-existing: anonymization, frameworks
  catalog/selection, HITL skip assert, report exports/docx)
- Characterization: `tests/test_graph_topology.py`,
  `tests/test_workflows_import_cycle.py`, `tests/test_credential_isolation.py`

## Known debt

- Façade still uses thin `*args, **kwargs` wrappers; followup/adhoc still call
  private methods on `AuditorGraph` (intentional back-compat).
- Soft target for `graph.py` (~300–500 lines) is ~770 lines of wrappers + init;
  further shrinking can inline wrappers once callers use workflows directly.
- Extraction script: `scripts/extract_graph_workflows.py` (historical; do not
  re-run blindly on a already-split tree).

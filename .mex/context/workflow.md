---
name: workflow
description: LangGraph orchestration, inventory-driven launch, HITL, resume, and multi-host scheduling.
triggers:
  - "workflow"
  - "langgraph"
  - "HITL"
  - "intake"
  - "resume"
  - "multi-host"
  - "audit plan"
edges:
  - target: context/architecture.md
    condition: for module boundaries
  - target: patterns/human-approval.md
    condition: for confirm and HITL gates
  - target: patterns/resume-execution.md
    condition: for checkpoint continue/resume
  - target: patterns/immutable-revisions.md
    condition: for plan revision lifecycle
grounds_to:
  - node: "function:cc3f52d6070cc766a4014aff3896a06c"
    fingerprint: "mh:64:2f2af11aa834367b761c8148a46c1f30ebdd8993e6bfc24325cdbd8428250524"
  - node: "class:68d8cf58cb1ff53b09033fa995f790fe"
    fingerprint: "mh:64:d10c38b420cb77843b484706e54df806478829f28ab8b4e4d1bf275641c95d9d"
last_updated: 2026-07-28
---

# Workflow

## Inventory-driven launch

Documented in `docs/inventory-driven-audit.md`.

1. Create `inventory/<ClientName>/` (`ClientName` ∈ `^[A-Za-z0-9_]+$`)
2. `psql-auditor inventory validate|analyze <Client>`
3. `psql-auditor audit plan <Client>` — builds/publishes immutable revision; does **not** execute
4. `psql-auditor audit start <Client> --confirm --plan-revision-id <id>` — pins revision; rejects stale
5. Service builds `AuditRequest` and calls `AuditorGraph.arun_request`

API mirrors this under `src/auditor/api/inventory_routes.py`.

## LangGraph topology

`graph.py` is a façade. Topology lives in [`build_main_graph`](mex://function:cc3f52d6070cc766a4014aff3896a06c) in `workflows/builder.py`.

Frozen node names (do not rename without checkpoint migration):

`route_framework` → `load_framework` → `collect_host_facts` → `assess_parallel` → (`reconnect_session` | `human_gate` | `finalize`)

Routers:

- `route_after_assess` → `{reconnect_session, human_gate, finalize}`
- `route_after_hitl` → `{assess_parallel, human_gate, finalize}`

Intake (when enabled): separate intake graph with `intake_gate` interrupt (`type=intake`), then framework jobs.

HITL interrupt payload: `type=skip_or_retry`. Resume via chat / `aresume` / `acontinue` with checkpoint under `CHECKPOINT_PATH` (default `artifacts/.checkpoints/auditor.sqlite`).

## Multi-host

`workflows/multi_runner.py` schedules per-host framework jobs with host locks, merges reports, and owns `arun` orchestration. Jobs are `AuditJob` under an `AuditRun` (`CORE-002`).

## Questionnaire / intake

Pre-audit intake collects client name, audit type, and related operator answers (`docs/pre-audit-intake.md`). Inventory may include `QUESTIONNAIRE.md` / `questionnaires/` — treated as operator inputs to planning, not as executable frameworks.

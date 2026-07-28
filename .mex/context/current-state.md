---
name: current-state
description: Accepted, partial, and open checklist work; limitations and debt. Update after every accepted PR.
triggers:
  - "status"
  - "checklist"
  - "acceptance"
  - "tech debt"
  - "current state"
edges:
  - target: context/decisions.md
    condition: for ADRs behind the state
  - target: context/architecture.md
    condition: for module ownership
grounds_to: []
last_updated: 2026-07-28
---

# Current project state

> **Maintenance rule:** Update this file in the same PR (or immediately after) whenever a checklist item is independently accepted. Mirror a short summary into `ROUTER.md` Current Project State.

Source of truth for IDs: `checklist/psql_auditor_master_refactoring_checklist (5).md` and `docs/defect-module-map.md`.

## Accepted tasks

- `AUD-001` baseline + defect map
- `AUD-002` unified local/CI quality gates
- `AUD-003` deterministic fixtures
- `CORE-001`…`CORE-005` identities, AssessmentResult, run-scoped artifacts
- `INPUT-001` strict `AuditRequest`
- `INPUT-003` validated inventory model

## Partial tasks (`[~]`)

- `CORE-006` — ApplicationRuntime exists; legacy globals remain
- `INPUT-002` / `AGENT-001` — Framework Registry; independent acceptance pending
- `INPUT-004` — Tool Registry + POC policy; WinRM/MCP transitional
- `INPUT-005` — Discovery + immutable plan store + confirm pin; independent acceptance pending
- `TOOL-001` — Registered SSH adapters
- `TOOL-002` — WinRM present, safety/tests incomplete
- `FLOW-003`, `FLOW-005`, `FLOW-006`, `FLOW-007` — reducer/timeouts/resume/singleton gaps
- `EVID-001`…`EVID-003`, `EVID-006`, `EVID-007` — SSH-normalized evidence path incomplete across transports
- `OPS-004` — modular cleanup ongoing

## Open tasks

- `TOOL-003`…`TOOL-005` HTTP / first-class TCP / SNMP adapters
- `FLOW-001`, `FLOW-002`, `FLOW-004` minimal state / Send / requirement subgraph
- `EVID-004`, `EVID-005` structured output + confidence
- `DB-*`, `HIST-*`, `EXC-*` warehouse/history/exceptions packages
- `REPORT-*`, `REVIEW-*`, `ANALYST-*` reporting and external review
- `OPS-001`…`OPS-003` error taxonomy, manifest, remove legacy MD parse from production

## Current limitations

- Operator `exclude_*` / `add_framework` adjustments do not publish derived plan revisions
- Plan confirmation metadata may live in compatibility views while revision `plan.json` stays draft bytes
- Anonymization and some report export paths have known baseline failures historically
- Integration tests often need `AUDITOR_TEST_DATABASE_URL` (local PG on host port 55432 in this environment)

## Known technical debt

- `graph.py` still ~thin `*args, **kwargs` wrappers; followup/adhoc call private methods
- Process-wide `get_auditor_graph*` deprecated but present
- Parallelism via `asyncio.gather` instead of LangGraph `Send`
- LLM fill path regex-parses JSON instead of structured output
- MEX graph DB must stay gitignored; regenerate with `npm run mex:graph`

## Recently landed (pending independent acceptance)

- Immutable plan revision store (`.audit_plans/revisions/`, lock, pointer, semantic idempotency)
- Required `plan_revision_id` on confirm/start (API 409 stale / CLI exit 4)

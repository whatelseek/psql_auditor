---
name: human-approval
description: Plan confirmation and LangGraph HITL skip/retry gates.
triggers:
  - "HITL"
  - "confirm"
  - "human_gate"
  - "approval"
edges:
  - target: context/workflow.md
    condition: topology
  - target: patterns/resume-execution.md
    condition: after interrupt
grounds_to: []
last_updated: 2026-07-28
---

# Human approval

## Context
Two gates: (1) plan confirm before jobs; (2) `human_gate` interrupt during assessment.

## Steps
1. Never create `AuditJob`s before confirmed plan + pinned revision.
2. On assess failures after reconnect policy, interrupt with `type=skip_or_retry` payload listing REQ ids.
3. Resume only through `aresume` / chat markers — do not forge checkpoint state.
4. Honor `HITL_ENABLED=false` auto-finalize with `error` statuses when intentionally disabling.

## Gotchas
- Confirming without `plan_revision_id` must 422 — do not default to latest pointer silently in new APIs.
- Intake interrupt is a separate `type=intake` payload.

## Verify
- [ ] Start without confirm rejected
- [ ] HITL resume returns to `assess_parallel` or finalize per router

## Debug
List interrupted sessions via `alist_sessions(interrupted_only=True)`.


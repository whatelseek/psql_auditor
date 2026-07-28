---
name: retry-policy
description: Session reconnect vs requirement retry vs plan re-analyze.
triggers:
  - "retry"
  - "reconnect_session"
  - "timeout"
edges:
  - target: context/workflow.md
    condition: routers
  - target: patterns/human-approval.md
    condition: HITL retry
grounds_to: []
last_updated: 2026-07-28
---

# Retry policy

## Context
Three different retry notions exist — do not conflate them.

## Steps
1. **Session errors** → `reconnect_session` then back to assess (automatic, limited).
2. **Requirement failures** → HITL `retry` / `retry all` after interrupt.
3. **Stale plan / inventory change** → re-analyze + new `plan_revision_id`, never retry start on stale pin.
4. Respect SSH/tool timeouts and `max_parallel_assessments`; do not invent unbounded tight loops.

## Gotchas
- `FLOW-005` graph-level backpressure is incomplete — use existing semaphores.
- Cancellation is best-effort (`cancel_audit_run`).

## Verify
- [ ] Reconnect path does not skip evidence write
- [ ] Stale start still fails closed

## Debug
Progress events / checkpoint thread id; SSH timeout settings in `Settings`.


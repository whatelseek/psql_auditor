---
name: immutable-revisions
description: Publish and consume immutable AuditPlan revisions with pinned plan_revision_id.
triggers:
  - "plan_revision_id"
  - "plan store"
  - "immutable plan"
  - "audit_plan_stale"
edges:
  - target: context/workflow.md
    condition: lifecycle
  - target: context/identity-model.md
    condition: ids
grounds_to: []
last_updated: 2026-07-28
---

# Immutable revisions

## Context
Plan bytes live under `.audit_plans/revisions/<plan_revision_id>/` via `inventory/plan_store.py`. Compatibility `latest.json` / pointer are not the authority for confirm/start.

## Steps
1. Build `AuditPlan` from inventory + discovery hashes in `inventory/plan.py`.
2. Publish with flock + temp dir + `os.rename`; validate `plan_revision_id` (`^prev-[0-9a-f]{16}$`).
3. Semantic idempotency: ignore only `AuditPlan.created_at` and `InventoryVersion.recorded_at` when detecting collisions.
4. Require `plan_revision_id` on confirm/start; mismatch → `audit_plan_stale` (HTTP 409 / CLI exit 4).
5. Never mutate files inside an existing revision directory.

## Gotchas
- Publishing pointer last (after compatibility files) with rollback on failure.
- Do not treat `latest.json` confirmation fields as mutating immutable `plan.json` draft bytes without an explicit derived-revision design.

## Verify
- [ ] Re-analyze with identical semantics does not collide spuriously
- [ ] Stale revision id rejected
- [ ] Tests in `tests/test_plan_revision_store.py` covered for your change

## Debug
Inspect `.audit_plans/revisions/`, `latest.pointer.json`, and service errors `plan_store_lock_failed` / `plan_revision_collision`.


---
name: idempotent-persistence
description: Safe re-entry for inventory versions, plan publish, and run registry writes.
triggers:
  - "idempotent"
  - "retry persist"
  - "version hash"
edges:
  - target: patterns/immutable-revisions.md
    condition: plans
  - target: context/identity-model.md
    condition: pins
grounds_to: []
last_updated: 2026-07-28
---

# Idempotent persistence

## Context
Operators re-run analyze/plan; API clients retry. Persistence must be semantically idempotent without corrupting immutable history.

## Steps
1. Key durable artifacts by content hash / version id where possible.
2. For plan store: identical semantics → reuse revision; do not invent a new id for timestamp-only churn.
3. Registry transitions (`AuditRegistry`) should reject illegal state jumps rather than half-apply.
4. Evidence writes should be append/versioned per requirement attempt — do not clobber provenance.

## Gotchas
- Wall-clock fields break naive byte equality — exclude documented volatile fields only.
- Locks: fail with `plan_store_lock_failed` rather than writing unlocked.

## Verify
- [ ] Double analyze/plan does not duplicate conflicting revisions
- [ ] Retry confirm with same revision is safe

## Debug
Compare hashes on `AuditPlan` and inventory `content_hash`.


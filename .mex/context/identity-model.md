---
name: identity-model
description: Canonical identities: client, run, job, plan revision, result_id and logical keys.
triggers:
  - "identity"
  - "client_id"
  - "audit_run_id"
  - "result_id"
  - "plan_revision_id"
edges:
  - target: context/architecture.md
    condition: for where identities flow
  - target: patterns/result-identity.md
    condition: when persisting or merging findings
  - target: patterns/immutable-revisions.md
    condition: for plan_revision_id
grounds_to: []
last_updated: 2026-07-28
---

# Identity model

## Client and run

| Identity | Meaning | Owner |
|----------|---------|-------|
| `client_id` | Customer / estate | `client_registry.require_client_id` |
| `audit_run_id` | One audit execution | `audit_registry`; must match client ownership |
| `audit_job_id` | Per-host/framework unit of work under a run | `AuditJob` in `domain/audit_models.py` |
| Legacy `run_id` | Evidence folder name only — not a substitute for `audit_run_id` | `evidence_store` |

Creating or persisting a run requires both `client_id` and `audit_run_id` (`CORE-001`). Reassignment across clients is rejected.

## Plan revision

| Identity | Meaning |
|----------|---------|
| `plan_id` | Logical plan for a client analyze cycle |
| `plan_revision_id` | Immutable bytes id (`prev-<16 hex>`); stored under `.audit_plans/revisions/<id>/` |
| Inventory `version_id` / `content_hash` | Pin of validated inventory used to build the plan |
| Discovery / framework / tool / policy hashes | Pins on `AuditPlan` — confirm/start fail closed if stale |

Confirm and start **must** receive the exact `plan_revision_id` the operator reviewed (`INPUT005-07` / plan store).

## Result identity (`CORE-003`)

Every persisted finding needs:

- `result_id` — unique UUID-like id (`new_result_id()`)
- Logical key: run + host/asset + framework + requirement (+ related dimensions in `ResultLogicalKey`)

`merge_result_maps` rejects duplicate logical keys with conflicting `result_id`. Historical comparison uses a stable subset of fields (`historical_comparison_key`).

## Request pin

`AuditRequest` (INPUT-001) is immutable v1: inventory version/hash, selected targets/frameworks, tool/policy snapshot hashes, secret-free. Stale pins fail closed before execution.

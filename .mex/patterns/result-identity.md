---
name: result-identity
description: Assign and merge canonical result_id + logical keys for findings.
triggers:
  - "result_id"
  - "logical key"
  - "merge_findings"
  - "CORE-003"
edges:
  - target: context/identity-model.md
    condition: model
  - target: context/evidence-model.md
    condition: persist path
grounds_to: []
last_updated: 2026-07-28
---

# Result identity

## Context
`domain/result_identity.py` + `result_identity_bind.py`. Every persisted finding needs `result_id` and a complete logical key.

## Steps
1. Create findings via `AssessmentResult` helpers so identity fields are present.
2. Call `validate_result_identity(..., for_persist=True)` before store writes.
3. Merge with `merge_result_maps` / `merge_findings` — never dict-overwrite by requirement id alone.
4. Use `historical_comparison_key` only for cross-run comparison, not as primary storage key.

## Gotchas
- Duplicate logical key with different `result_id` must raise — do not silently pick one.
- Legacy maps keyed only by requirement id are transitional.

## Verify
- [ ] `tests/test_canonical_result_identity.py` still meaningful for the change
- [ ] No finding persisted without `result_id`

## Debug
`IncompleteResultIdentityError`, `DuplicateLogicalKeyError`.


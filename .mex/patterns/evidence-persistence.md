---
name: evidence-persistence
description: Write run-scoped evidence with ownership checks.
triggers:
  - "EvidenceStore"
  - "write_tool_result"
  - "artifacts"
edges:
  - target: context/evidence-model.md
    condition: model
  - target: patterns/tool-provenance.md
    condition: hashes
grounds_to: []
last_updated: 2026-07-28
---

# Evidence persistence

## Context
`EvidenceStore` + run registry on the façade. Artifacts are runtime data — never copy into `.mex/`.

## Steps
1. Resolve store from `audit_run_id` / state helpers — do not write to a global folder.
2. Assert client owns run before write.
3. Write tool results via normalized helpers; keep requirement folder layout stable.
4. On finalize, leave evidence immutable for that attempt; new attempts get new files/ids.

## Gotchas
- Mixing clients in one evidence root breaks CORE-001 ownership.
- Large outputs: respect truncation policy without silent meaning loss (`EVID-007` open).
- `rebind_run_id` must not transplant a source `ownership.json` into a new `audit_run_id` path; after move, ownership is rewritten to the destination identity when provided.
- Intake resumes re-run `intake_gate`; durable `client_id` / `audit_run_id` are restored from meta, but questionnaire answers are not (interrupt replay order).

## Verify
- [ ] Evidence path includes run id
- [ ] Ownership mismatch raises

## Debug
`EvidenceRegistry` keys; `ClientOwnershipError`.


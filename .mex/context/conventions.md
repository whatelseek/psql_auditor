---
name: conventions
description: Coding conventions for psql_auditor — layout, typing, tests, secrets, MEX hygiene.
triggers:
  - "convention"
  - "style"
  - "naming"
  - "tests"
  - "lint"
edges:
  - target: context/setup.md
    condition: for exact commands
  - target: patterns/INDEX.md
    condition: for task-specific patterns
grounds_to: []
last_updated: 2026-07-28
---

# Conventions

## Layout

- Production code under `src/auditor/`; tests under `tests/`
- Domain types in `domain/`; side-effecting I/O in inventory/tools/stores/workflows
- Workflows must not import `auditor.graph` (depend on `workflows.protocols.AuditRuntime`)

## Style

- Prefer explicit fail-closed errors with stable `code=` strings (e.g. `audit_plan_stale`, `tool_unauthorized`)
- No plaintext secrets in domain models, API responses, logs, or MEX
- Prefer small typed dataclasses / TypedDicts already used in-repo over new parallel models

## Tests

- Use `.venv/bin/python` and project Makefile targets
- Prefer fixtures from `tests/fixtures/canonical_audit.py` and `DeterministicFakeChatModel`
- Do not mark checklist parents accepted without independent review evidence

## Verify checklist

- [ ] `make lint` / typecheck clean for touched paths (or full `make check` when required)
- [ ] Targeted pytest for the subsystem green
- [ ] No secrets in diffs; inventory fixtures use `secret_ref` where asserting persistence
- [ ] If architecture changed: update `.mex/context/*`, `context/current-state.md`, bump `last_updated`
- [ ] `npm run mex:check` when editing `.mex/`

## MEX hygiene

- Edit Markdown under `.mex/`; never commit `.mex/graph.db` or `*.db*`
- Route via `ROUTER.md` — do not dump the whole wiki into every prompt

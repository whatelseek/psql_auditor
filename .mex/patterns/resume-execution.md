---
name: resume-execution
description: Resume HITL interrupts and continue after disconnect via checkpoints.
triggers:
  - "aresume"
  - "acontinue"
  - "checkpoint"
  - "continue"
edges:
  - target: context/workflow.md
    condition: runner
  - target: patterns/human-approval.md
    condition: interrupt payload
grounds_to: []
last_updated: 2026-07-28
---

# Resume execution

## Context
`workflows/runner.py`: `aresume`, `acontinue`; checkpoints under `CHECKPOINT_PATH`.

## Steps
1. Ensure async checkpointer (`ensure_async_checkpointer`) before run/resume.
2. Pass the same `thread_id` / audit run markers the interrupt emitted.
3. Multi-host: use `_continue_multi_after_resume` paths — do not restart sibling hosts blindly.
4. Prefer `acontinue` for disconnect mid-run without HITL decision.
5. Intake (`:intake` threads): resume on the process `intake_graph` (same saver as `arun_intake`). Pre-identity `audit-{hex}:intake` is allowed when a multi-session entry or interrupted checkpoint exists; HITL still requires `client_id` + `audit_run_id`.

## Gotchas
- Renaming graph nodes breaks checkpoint compatibility.
- Process restart is OK if sqlite checkpoint path is durable; memory checkpointer is not.
- Do not switch intake resume onto a scoped checkpointer lease before `intake_complete` — checkpoints were written pre-identity on the process saver.

## Verify
- [ ] Interrupt → resume smoke test for your change
- [ ] No duplicate `result_id` on resumed assess

## Debug
`alist_status` / checkpoint sqlite; Open WebUI `[AUDIT_HITL:…]` / `[AUDIT_CONTINUE:…]` markers.


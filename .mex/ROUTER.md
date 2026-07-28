---
name: router
description: Session bootstrap and navigation hub. Read at the start of every session before any task. Contains project state, routing table, and behavioural contract.
edges:
  - target: context/architecture.md
    condition: when working on system design or how modules connect
  - target: context/workflow.md
    condition: when changing LangGraph topology, intake, HITL, or multi-host scheduling
  - target: context/identity-model.md
    condition: when touching client_id, audit_run_id, plan_revision_id, or result identity
  - target: context/frameworks.md
    condition: when editing Markdown frameworks under agents/ or FrameworkRegistry
  - target: context/capability-model.md
    condition: when selecting tools or HostCapabilitySnapshot
  - target: context/tool-security.md
    condition: when changing Tool Registry, policies, SSH allow-lists, or MCP
  - target: context/evidence-model.md
    condition: when persisting ToolResult or EvidenceStore paths
  - target: context/reporting.md
    condition: when changing finalize, report render, or reconciliation
  - target: context/anonymization.md
    condition: when working on report anonymization / external review
  - target: context/decisions.md
    condition: when making or revisiting architectural choices
  - target: context/current-state.md
    condition: when planning work, acceptance, or updating after an accepted PR
  - target: context/conventions.md
    condition: when writing or reviewing code
  - target: context/stack.md
    condition: when choosing libraries or runtime versions
  - target: context/setup.md
    condition: when setting up the environment or running gates
  - target: patterns/INDEX.md
    condition: when starting any implementation task
  - target: SETUP.md
    condition: when onboarding to this MEX scaffold
  - target: SYNC.md
    condition: when realigning scaffold after large refactors
last_updated: 2026-07-28
---

# Session Bootstrap

If you have not read `AGENTS.md`, read it now. Then read this file fully before doing anything else.

## Current Project State

**Working:**
- Inventory validate/analyze → immutable plan revisions → confirm/start with pinned `plan_revision_id`
- LangGraph assessment loop with HITL interrupt, reconnect, checkpoint resume
- Framework Registry over Markdown files in the agents directory; Tool Registry + POC capability policy; SSH `ssh_run` / `ssh_read_file`
- Canonical result identity (`result_id` + logical key); secret-free inventory/plan/request persistence

**Not yet built / incomplete:**
- Full WinRM/HTTP/TCP/SNMP registered adapters (TOOL-002…005)
- Reporting package (REPORT-*), external review package (REVIEW-*), analyst Excel import (ANALYST-*)
- Governed agent runtime (AGENT-001); typed minimal graph state / Send fan-out (FLOW-*)

**Known issues:**
- `INPUT-005` / `INPUT-004` / `TOOL-001` remain `[~]` pending independent acceptance
- Process-wide graph getters still exist for compat (`FLOW-007`); façade wrappers in `graph.py`
- Operator plan adjustments (`exclude_*` / `add_framework`) do not yet create derived revisions

Detail: [`context/current-state.md`](context/current-state.md). Update that file after every accepted PR.

## Routing Table

Load **only** the files needed for the task. Do not load the entire wiki.

| Subsystem | Load |
|-----------|------|
| Inventory (loaders, normalize, secrets) | `context/architecture.md` + `context/identity-model.md` + `patterns/idempotent-persistence.md` |
| Discovery (SSH/WinRM collectors, HostCapability) | `context/capability-model.md` + `context/tool-security.md` + `patterns/capability-resolution.md` |
| Planning (`AuditPlan`, plan store, confirm/start) | `context/workflow.md` + `patterns/immutable-revisions.md` + `patterns/human-approval.md` |
| Framework Registry | `context/frameworks.md` |
| Questionnaire Registry / intake questionnaires | `context/workflow.md` (intake) + inventory docs under `docs/inventory-driven-audit.md` |
| Tool Registry | `context/tool-security.md` + `patterns/capability-resolution.md` + `patterns/tool-provenance.md` |
| MCP Registry | `context/tool-security.md` + `context/stack.md` |
| Workflow (LangGraph nodes, multi-runner) | `context/workflow.md` + `patterns/retry-policy.md` + `patterns/resume-execution.md` |
| Evidence | `context/evidence-model.md` + `patterns/evidence-persistence.md` + `patterns/result-identity.md` |
| Reporting | `context/reporting.md` + `patterns/report-reconciliation.md` |
| Knowledge Base / playbooks | `context/architecture.md` (memory) + `docs/long-term-memory.md` |
| Acceptance review / checklist status | `context/current-state.md` + `context/decisions.md` |
| Writing code / conventions | `context/conventions.md` + matching pattern from `patterns/INDEX.md` |
| Design decision / ADR | `context/decisions.md` |

Always load `context/architecture.md` first if not already in context this session **when** the task spans more than one subsystem.

## Behavioural Contract

1. **CONTEXT** — Load routed files; narrate what you load. Check `patterns/INDEX.md`.
2. **BUILD** — Follow patterns; announce deviations before coding.
3. **VERIFY** — Run conventions verify checklist item-by-item; prefer `make check` / targeted pytest.
4. **DEBUG** — Use pattern Debug sections; prefer `mex graph` over blind grep.
5. **GROW** — Update `context/current-state.md` / ROUTER state after accepted work; add patterns when tasks recur; bump `last_updated`.

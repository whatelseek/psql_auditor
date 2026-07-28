---
name: decisions
description: ADR-style architectural decisions for the Infrastructure Auditor.
triggers:
  - "ADR"
  - "decision"
  - "why"
  - "architecture decision"
edges:
  - target: context/architecture.md
    condition: for the resulting shape
  - target: context/current-state.md
    condition: for implementation status of each decision
grounds_to: []
last_updated: 2026-07-28
---

# Architectural decisions (ADR)

## ADR-001 — LangGraph orchestration

**Status:** Accepted (evolving)  
**Decision:** Orchestrate audits as a LangGraph `StateGraph` with named nodes, conditional routers, interrupts, and SQLite/memory checkpointer.  
**Why:** Audits are long-running, cyclic (reconnect/HITL), and must resume after chat disconnects.  
**Consequences:** Node/router names are frozen contracts; logic lives under `workflows/`; `graph.py` is a façade. Open: Send fan-out, minimal state (`FLOW-*`).

## ADR-002 — Inventory-driven execution

**Status:** Accepted (INPUT-003 done; INPUT-005 partial)  
**Decision:** Execution starts from validated `ClientInventory` under `inventory/<Client>/`, not free-form chat alone for production launches.  
**Why:** Reproducible scope, secret-free pins, multi-host targeting.  
**Consequences:** Analyze/plan/confirm/start CLI+API; chat intake remains for interactive paths.

## ADR-003 — Immutable execution plans

**Status:** Accepted (plan store on main)  
**Decision:** Each published plan is an immutable `plan_revision_id` directory; confirm/start pin that id; semantic idempotency ignores only volatile timestamps.  
**Why:** Operators must not confirm a newer `latest.json` than reviewed.  
**Consequences:** Compatibility `latest.json` / pointer files; lock + atomic rename publish; derived operator adjustments still open.

## ADR-004 — Capability-based tool selection

**Status:** Accepted (INPUT-004 / TOOL-001 partial)  
**Decision:** Tools are selected and bound through Tool Registry + capability policy + host capability snapshots — not ad-hoc LLM tool lists.  
**Why:** Fail-closed authorization, auditability, hash pins on plans/runs.  
**Consequences:** Unauthorized tools never bind; discovery uses registry transports.

## ADR-005 — Evidence-first assessment

**Status:** Accepted (EVID-* partial)  
**Decision:** Persist normalized tool evidence before (or as input to) status assessment; findings reference evidence/provenance.  
**Why:** Defensible audits; reduces hallucinated observations.  
**Consequences:** `ToolResult` + `EvidenceStore`; structured LLM output still incomplete.

## ADR-006 — Human approval gates

**Status:** Accepted  
**Decision:** (1) Plan confirmation before any `AuditJob` execution; (2) LangGraph HITL interrupt on failed requirements (`skip_or_retry`); (3) optional intake interrupt.  
**Why:** Destructive/misleading automation risk; operator accountability.  
**Consequences:** `HITL_ENABLED`; Open WebUI resume markers; cancellation still best-effort.

## ADR-007 — Versioned Framework Registry

**Status:** Accepted (INPUT-002 partial)  
**Decision:** Frameworks are versioned Markdown assets validated by `FrameworkRegistry`, with deterministic version from content hash.  
**Why:** Admin-extensible checklists without code deploys; prompt compactness.  
**Consequences:** Executable vs catalog-only split; fail-closed loaders.

## ADR-008 — Tool Registry

**Status:** Accepted (partial coverage)  
**Decision:** JSON manifests under `tools/catalog/` plus policy profiles define the only production tool surface.  
**Why:** Uniform validation, hashes, and transport metadata.  
**Consequences:** New transports require catalog + adapter + tests; WinRM/HTTP/SNMP gaps remain.

## ADR-009 — Knowledge Base (product memory)

**Status:** Accepted (limited)  
**Decision:** Runtime learned playbooks live in `src/auditor/memory/` (and related docs), separate from MEX.  
**Why:** Operational reuse across audits without polluting architectural wiki or committing customer evidence into `.mex/`.  
**Consequences:** Agents must not write audit artifacts into `.mex/context`.

## ADR-010 — Client Baseline

**Status:** Accepted (AUD-001…003)  
**Decision:** Reproducible baseline docs, defect→module map, unified `make check` gates, and deterministic fixtures (`FixedClock`, canonical scenario) gate quality.  
**Why:** Prevent silent regressions during large refactor.  
**Consequences:** Checklist + `docs/baseline.md` + CI are sources of acceptance truth alongside independent PR review.

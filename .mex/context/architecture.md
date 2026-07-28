---
name: architecture
description: How Infrastructure Auditor modules connect: inventory → plan → LangGraph → evidence → report.
triggers:
  - "architecture"
  - "system design"
  - "modules"
  - "integration"
  - "inventory"
  - "knowledge base"
edges:
  - target: context/workflow.md
    condition: when changing LangGraph or execution lifecycle
  - target: context/identity-model.md
    condition: when identities or ownership matter
  - target: context/decisions.md
    condition: when asking why the architecture is shaped this way
  - target: context/current-state.md
    condition: when checking what is implemented
grounds_to:
  - node: "class:68d8cf58cb1ff53b09033fa995f790fe"
    fingerprint: "mh:64:d10c38b420cb77843b484706e54df806478829f28ab8b4e4d1bf275641c95d9d"
  - node: "function:cc3f52d6070cc766a4014aff3896a06c"
    fingerprint: "mh:64:2f2af11aa834367b761c8148a46c1f30ebdd8993e6bfc24325cdbd8428250524"
  - node: "class:a76e423f08f4386bde84cb33bfff24ca"
    fingerprint: "mh:64:3fe5e65f2900b03062414364e5734d3754c668f6e5b9990ca983b2d8d69c1c5c"
  - node: "class:807cb593a848237fd63c2263f1d5a555"
    fingerprint: "mh:64:79adb3ab1e3539906e69433e29f889b313dd8b95f9e88cd37c01278535f284e7"
  - node: "class:633d2124eb32645f82169eb665c53f3f"
    fingerprint: "mh:64:01f6e260dcccc49ad6ab95f045cbc682a927419e3a56f5a061b3fc2646638ee0"
last_updated: 2026-07-28
---

# Architecture

## Purpose

`psql_auditor` is an **Infrastructure Auditor**: operators describe a client estate in `inventory/<Client>/`, the system discovers host capabilities, builds an immutable `AuditPlan`, and after human confirmation runs LangGraph workflows that gather tool evidence, assess framework requirements, pause for HITL when needed, and finalize reports.

MEX (`.mex/`) stores **architectural memory for AI agents**. It must never hold audit evidence, customer reports, credentials, or runtime state (`artifacts/`, `.audit_plans/`, inventory secrets, checkpoints).

## Primary flow

```text
inventory/<Client>/
  → validate / normalize (ClientInventory, secret_ref only)
  → discover (ToolRegistry-selected SSH/WinRM collectors)
  → HostCapabilitySnapshot + framework applicability
  → AuditPlan (hashes pinned) → plan_revision_id store
  → human confirm (exact plan_revision_id)
  → AuditRequest → arun_request / multi-host jobs
  → LangGraph: route → load framework → host facts → assess_parallel
       ↻ reconnect_session | human_gate (interrupt)
  → EvidenceStore + AssessmentResult
  → finalize report → optional anonymize / follow-up
  → optional playbook / knowledge update
```

## Module map

| Area | Location | Role |
|------|----------|------|
| Façade | `src/auditor/graph.py` | [`AuditorGraph`](mex://class:68d8cf58cb1ff53b09033fa995f790fe) public API; thin wrappers over workflows |
| Workflows | `src/auditor/workflows/` | LangGraph topology, intake, discovery nodes, assessment, HITL, finalize, runners |
| Domain | `src/auditor/domain/` | `AuditRequest`, `AuditPlan`, inventory, `AssessmentResult`, `ToolResult`, identities |
| Inventory | `src/auditor/inventory/` | Loaders, discovery, plan build, `plan_store` immutable revisions, service/CLI |
| Registries | `framework_registry.py`, `tool_registry.py`, `mcp_registry.py`, `client_registry.py`, `audit_registry.py` | Versioned catalogs and run lifecycle |
| Tools | `src/auditor/tools/` | SSH, WinRM, Postgres, MCP client, secret redaction |
| API / CLI | `src/auditor/api/`, `cli.py` | HTTP + `psql-auditor` entry points |
| Frameworks | `agents/postgres_cis.md` (and siblings) | Administrator Markdown checklists |
| Tool catalog | `tools/catalog/`, `tools/policies/` | Manifests + capability policy JSON |
| MCP catalog | `mcps/registry.json` | Enabled MCP servers |
| Memory | `src/auditor/memory/` | Learned playbooks (runtime; not MEX) |

## Architectural boundaries

- **LLM does not execute tools.** Binding goes through `ToolRegistry.bindable_langchain_tools` under capability policy.
- **Inventory facts vs discovery facts.** Discovery reconciles into snapshots; it must not silently overwrite declared inventory facts.
- **Plans are immutable by revision.** Working/compatibility views may show confirmation; bytes under `.audit_plans/revisions/<plan_revision_id>/` do not change.
- **Evidence ≠ assessment.** Tool outputs land in `EvidenceStore`; findings are `AssessmentResult` with result identity.
- **Secrets are references.** Plaintext only at live connect time via runtime target ContextVar.

## Knowledge Base

Long-term operator memory for playbooks lives under `src/auditor/memory/` and `docs/long-term-memory.md`. That is **runtime product memory**, separate from MEX architectural wiki. Do not conflate the two.

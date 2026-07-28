---
name: evidence-model
description: ToolResult schema, EvidenceStore layout, provenance, and evidence-first assessment.
triggers:
  - "evidence"
  - "ToolResult"
  - "EvidenceStore"
  - "provenance"
edges:
  - target: context/identity-model.md
    condition: for result_id binding
  - target: patterns/evidence-persistence.md
    condition: when writing evidence
  - target: patterns/result-identity.md
    condition: when merging assessments
grounds_to: []
last_updated: 2026-07-28
---

# Evidence model

## Evidence-first

Assessment must be grounded in collected tool output. Workflow: execute tools → persist `ToolResult` / sidecars → LLM/rules fill Status/Observation/Recommendation from evidence — not the reverse.

## ToolResult

`domain/tool_result.py` — normalized `tool_result.v1` (status, output, error, identity, target, timestamps, provenance). SSH path is the reference implementation (`EVID-001`…`003` partial).

`ToolProvenance` carries client/run/framework/requirement/asset plus catalog/policy hashes and command hash where applicable.

## EvidenceStore

`evidence_store.py` — per-run folders under artifacts; requirement-scoped command result files; ownership checks via `client_id`/`audit_run_id`. Registry of stores is run-scoped on the graph façade (`EvidenceRegistry`).

## Gaps

Non-SSH tools still use transitional sidecars. Structured LLM output binding (`EVID-004`), sufficiency/confidence (`EVID-005`), and hard immutability of framework fields (`EVID-006`) remain open checklist items.

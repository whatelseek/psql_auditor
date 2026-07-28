---
name: reporting
description: Finalize, report render formats, and reconciliation with structured assessments.
triggers:
  - "report"
  - "finalize"
  - "markdown"
  - "docx"
  - "excel"
  - "reconciliation"
edges:
  - target: context/evidence-model.md
    condition: for inputs to assessment
  - target: context/anonymization.md
    condition: for review-safe exports
  - target: patterns/report-reconciliation.md
    condition: when regenerating reports
grounds_to: []
last_updated: 2026-07-28
---

# Reporting

## Current path

`workflows/finalize.py` / `AuditorGraph.finalize` renders the checklist report (Status / Observation / Recommendation per requirement), persists session/results, and packages artifacts (including ZIP for chat). Multi-host merges via `_merge_multi_reports`.

Follow-up intents: revise requirement, refill finding, update report, anonymize (`graph.py` `arun_*` entry points). See `docs/post-audit-followup.md`.

## Constraints

- Report generation must **not** rewrite immutable framework requirement text (title, severity, pass criteria from checklist)
- Findings carry result identity; regeneration should reconcile by `result_id` / logical key, not blind overwrite
- Warehouse live upsert paths exist in results store — full REPORT-* package (versioned `ReportDataset`, checksums, atomic publish) is **not** accepted yet

## Target direction (checklist)

`REPORT-001`…`REPORT-012` define a separate reporting package, metrics engine, Excel/Word management reports, and atomic versioned publish. Until then, treat finalize Markdown/ZIP as the production path and keep changes localized.

---
name: report-reconciliation
description: Regenerate reports without losing result identity or mutating framework text.
triggers:
  - "reconcile report"
  - "finalize"
  - "update report"
edges:
  - target: context/reporting.md
    condition: pipeline
  - target: patterns/result-identity.md
    condition: ids
grounds_to: []
last_updated: 2026-07-28
---

# Report reconciliation

## Context
Finalize and follow-up (`arun_update_report`, refill, revise) must reconcile structured findings with rendered Markdown/ZIP.

## Steps
1. Load findings by `result_id` / logical key.
2. Re-render checklist sections; copy immutable framework fields from registered requirements.
3. Do not invent statuses without evidence or analyst override hooks (ANALYST-* not accepted yet).
4. Multi-host: merge via existing multi_runner merge helpers.

## Gotchas
- Blind overwrite by requirement id loses identity history.
- Full `ReportDataset` package not landed — keep changes compatible with current finalize.

## Verify
- [ ] Framework instruction text unchanged after regenerate
- [ ] result_ids stable across refill when logically same

## Debug
Compare `AssessmentResult` maps before/after finalize.


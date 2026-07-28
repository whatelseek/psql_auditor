---
name: anonymization
description: Report anonymization for external review and de-anonymization constraints.
triggers:
  - "anonymize"
  - "review"
  - "PII"
  - "external model"
edges:
  - target: context/reporting.md
    condition: for report pipeline
  - target: context/decisions.md
    condition: for review-related ADRs
grounds_to: []
last_updated: 2026-07-28
---

# Anonymization

## Current capability

`arun_anonymize_report` provides an operator path to produce a redacted/anonymized report view for safer sharing. Implementation is transitional; several baseline tests historically failed around anonymization completeness.

## Target (REVIEW-*)

Checklist defines versioned `ReviewPackage`, reversible anonymization map, leak detection before send, external-model adapter, response validation, atomic de-anonymization, and persistence of reviews into effective results (`REVIEW-001`…`009`).

## Rules for agents

- Never commit customer-identifying audit content into `.mex/`
- Prefer secret redaction helpers already used on tool I/O
- Do not log plaintext credentials when debugging anonymization
- Until REVIEW-* is accepted, treat anonymization as best-effort and call out residual leak risk in PRs

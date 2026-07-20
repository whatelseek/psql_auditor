# CIS compliance charts (Open WebUI)

Visualize auditor CIS results as **compliance % bar charts by severity**.

## What you get

- Table: Overall + Critical / High / Medium / Low …
- Horizontal **SVG bar chart** (0–100%)
- Formula: `(pass + 0.5 × partial) / assessed × 100`  
  (`skipped` is excluded from the denominator)

## Install in Open WebUI

### A) Tool (call from chat)

1. Open WebUI → **Workspace → Functions** (or Admin → Functions)
2. Create function → paste  
   [`openwebui/functions/cis_compliance_charts.py`](../openwebui/functions/cis_compliance_charts.py)
3. Enable it and grant the tool to model `auditor` (or your chat)
4. After an audit, ask:

   `Visualize CIS compliance from this report`  
   (or paste the report into `visualize_cis_compliance`)

### B) Filter (auto-append)

1. Create another function → paste  
   [`openwebui/functions/cis_compliance_charts_filter.py`](../openwebui/functions/cis_compliance_charts_filter.py)
2. Set type **Filter**, enable **Outlet**
3. Attach the filter to the model / chat
4. Every auditor reply that contains a Summary table gets charts appended automatically

## Agent-side charts

The auditor can also append the same chart block to the final report when:

```env
COMPLIANCE_CHARTS_IN_REPORT=true
```

(default on). Disable if you only want the Open WebUI filter.

## Example chart metrics

| Severity | Example |
|----------|---------|
| Overall | 62.5% |
| Critical | 0% |
| High | 75% |
| Medium | 100% |

Parsed from the report Markdown summary table:

`| ID | Title | Severity | Status | … |`

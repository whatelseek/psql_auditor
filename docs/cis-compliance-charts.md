# CIS compliance charts (Open WebUI)

Visualize auditor CIS results as **compliance % bar charts by severity**.

## What you get

- Table: Overall + Critical / High / Medium / Low …
- Horizontal **SVG bar chart** (0–100%)
- Formula: `(pass + 0.5 × partial) / assessed × 100`  
  (`skipped` is excluded from the denominator)

## Install in Open WebUI

Important: current Open WebUI splits **Tools** and **Functions**.

| File | Install where | Required class |
|------|---------------|----------------|
| `cis_compliance_charts.py` | **Workspace → Tools** (not Functions) | `class Tools` |
| `cis_compliance_charts_filter.py` | **Workspace → Functions** | `class Filter` |

Pasting the Tools file into Functions fails with:
`No Function class found in the module`.

### A) Tool (call from chat)

1. Open WebUI → **Workspace → Tools**
2. Create tool → paste  
   [`openwebui/functions/cis_compliance_charts.py`](../openwebui/functions/cis_compliance_charts.py)
3. Enable it and grant the tool to model `auditor` (or your chat)
4. After an audit, ask:

   `Visualize CIS compliance from this report`  
   (or paste the report into `visualize_cis_compliance`)

### B) Filter (auto-append)

1. Create a function → paste  
   [`openwebui/functions/cis_compliance_charts_filter.py`](../openwebui/functions/cis_compliance_charts_filter.py)
2. Confirm type **Filter** (auto-detected from `class Filter`)
3. Enable the function **and turn on Global** (required for auto-run on every chat)
4. Optionally also attach it under the model’s Filters
5. Every auditor reply that contains a Summary table / `REQ-*` rows gets charts appended automatically

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

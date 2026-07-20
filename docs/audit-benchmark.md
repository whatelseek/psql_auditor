# Audit benchmark history (`benchmark.md`)

After each **completed checklist audit**, the agent appends aggregate scores to a cumulative Markdown ledger:

```text
memory/benchmark.md
memory/benchmark.jsonl   # machine-readable companion (source of truth)
```

This is **not** the CIS checklist itself (`agents/*.md`). It is a **history of past audit results**.

## What is stored

| Field | Meaning |
|-------|---------|
| `finished_at` | UTC timestamp |
| `run_id` | Evidence run id |
| `framework` | e.g. `ubuntu_cis` |
| pass / fail / partial / error / skipped | Status counts |
| `assessed` | Non-skipped requirements |
| `compliance_%` | `(pass + 0.5×partial) / assessed × 100` |
| `evidence` | Relative path under `EVIDENCE_DIR` |

**Never stored:** observations, recommendations, tool stdout, credentials, or the operator prompt.

## Sections in the file

1. **Latest by framework** — most recent row per framework (quick trend view)
2. **Full history** — every completed audit (newest first)

## When it updates

On graph **finalize** for each framework (including multi-framework runs — one row per framework). Ad-hoc command runs do not write here.

## Config

```env
BENCHMARK_ENABLED=true
# Optional override (default: <MEMORY_DIR>/benchmark.md)
# BENCHMARK_PATH=memory/benchmark.md
MEMORY_DIR=memory
```

Docker already mounts `./memory`, so the ledger survives container restarts.

## Related

- Compliance charts: [`cis-compliance-charts.md`](cis-compliance-charts.md)
- Evidence folders: README “Evidence on disk”

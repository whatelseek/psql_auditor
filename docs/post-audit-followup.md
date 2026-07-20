# Post-audit follow-up (revise REQ + update report)

After a checklist audit finishes, you can **collect more evidence for a specific REQ**
into the **same** `artifacts/<run_id>/<framework>/REQ-NNN/` folder, then **rebuild**
the Markdown report / ZIP from the updated findings.

## Flow

```text
1. Audit completes → evidence path + ZIP in chat
2. Revise / re-check a requirement (new tool logs append as 003_…, 004_…)
3. Ask to update the report → report.md + ZIP regenerated
```

## Chat examples

```text
Revise REQ-002 on Ubuntu
Run another check for REQ-002: `sshd -T | grep -i permitrootlogin`
Проверь REQ-001 ещё раз
Перепроверь REQ-003 postgres

Update the report
Update the report from new evidence
Обнови отчёт
```

## Behaviour

| Ask | What happens |
|-----|----------------|
| **Revise / re-check REQ** | Opens the latest (or mentioned) audit run, runs tools via the normal evidence gatherer, **appends** logs under that REQ folder, overwrites `finding.json` |
| **Update the report** | Rebuilds `report.md` from all `finding.json` on disk (optional per-framework), re-packages ZIP |

Run selection order: explicit `run_id` in the message → evidence path / download link in chat history → newest folder under `EVIDENCE_DIR`.

If no prior audit exists, a REQ revise falls back to an **ad-hoc** run (new folder) and says so.

## Related

- Ad-hoc commands (no checklist): [`adhoc-commands.md`](adhoc-commands.md)
- Starting audits: [`starting-an-audit.md`](starting-an-audit.md)
- Russian manual: [`user-manual-ru.md`](user-manual-ru.md)

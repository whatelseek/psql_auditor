# Post-audit follow-up (three-step)

After a checklist audit finishes, refine a requirement in **three chat steps**
without re-running the whole framework. Evidence stays under the same
`artifacts/<client>/<host>/<framework>/REQ-NNN/` folder (or
`artifacts/<client>/<framework>/REQ-NNN/` for single-host runs).

## Flow

```text
1. Audit completes → evidence path + ZIP in chat
2. Gather evidence  → tools append (003_…, 004_…) — cells unchanged
3. Refill finding   → rewrite Status / Observation / Recommendation from disk
4. Update report    → rebuild report.md + ZIP
```

You may **repeat steps 2–3 for other REQs** before step 4. One final
**Update the report** rebuilds everything from disk.

One-shot alternative: `Revise REQ-…` still gathers **and** refills in a single turn
(then still ask to update the report).

## Chat examples

```text
# Step 1 — tools only (no cell overwrite); include host when multi-host
Evaluate REQ-001 on ubuntu_cis for host 10.200.29.78.
Look for PermitRootLogin. Use: sshd -T | grep -i permitrootlogin

Gather evidence for REQ-002: `sshd -T | grep -i permitrootlogin`
Проверь REQ-001 ещё раз

# Step 2 — rewrite cells from stored evidence
Prepare new observation and recommendation for REQ-001
Обнови наблюдение для REQ-002

# (optional) another REQ before rebuilding
Evaluate REQ-005 on ubuntu_cis for host 10.200.29.78. Check …
Prepare new observation and recommendation for REQ-005

# Step 3 — rebuild report / ZIP once
Update the report
Обнови отчёт

# One-shot (gather + refill)
Revise REQ-002 on ubuntu_cis for host 10.200.29.78
```

Open WebUI slash shortcuts (model **auditor**): `/gather-req`,
`/refill-req`, `/revise-req`, `/update-report` — see
[`owui-slash-commands.md`](owui-slash-commands.md).

## Behaviour

| Ask | What happens |
|-----|----------------|
| **Evaluate / gather evidence for REQ** | Opens the latest (or mentioned) audit run, **binds SSH to the named host** when evidence is under `host/framework`, runs tools, **appends** logs under that REQ folder; does **not** overwrite observation/recommendation |
| **Prepare / refill observation** | Re-reads tool logs + `finding.json`, rewrites status/observation/recommendation for the named REQ (or last `revised_reqs` in run meta). Does **not** refill every requirement in the run |
| **Revise REQ** | Gather + refill in one step (with SSH bind when host is known) |
| **Update the report** | Rebuilds per-host/framework `report.md` and root `report.md` from all `finding.json` on disk, re-packages ZIP |

Run selection order: explicit `run_id` / client folder in the message → evidence path / download link in chat history → newest folder under `EVIDENCE_DIR`.

When the same REQ exists on **multiple hosts**, name the host (and framework), e.g.
`for host 10.200.29.78` or `` `10.200.29.78/ubuntu_cis` ``.

If no prior audit exists, a REQ revise falls back to an **ad-hoc** run (new folder) and says so.

Playbook-only commands (`Run playbook commands for REQ-002`) use the **ad-hoc** path (deterministic playbook), which can still append into the latest audit run when one exists.

## Related

- Ad-hoc commands (no checklist): [`adhoc-commands.md`](adhoc-commands.md)
- Starting audits: [`starting-an-audit.md`](starting-an-audit.md)
- Russian manual: [`user-manual-ru.md`](user-manual-ru.md)

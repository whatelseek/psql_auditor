# Open WebUI — agent test checklist

Manual QA checklist for verifying **auditor** through Open WebUI. Use a
fresh chat (or a dedicated lab client) per full run. Mark each item as you go.

Related docs: [starting-an-audit.md](starting-an-audit.md) ·
[owui-slash-commands.md](owui-slash-commands.md) ·
[results-database.md](results-database.md) ·
[post-audit-followup.md](post-audit-followup.md)

**Lab client name used below:** `________________`  
**Session # observed:** `________________`  
**Date / tester:** `________________`

---

## 0. Preconditions

- [ ] `docker compose` stack is up (`agent`, `open-webui`, `results-db`)
- [ ] Open WebUI opens in the browser; model **auditor** is selectable
- [ ] `.env` has `RESULTS_DB_ENABLED=true` and a valid `RESULTS_DATABASE_URL`
- [ ] Inventory exists: `inventory/<Client>/INVENTORY.md` with Credentials / SSH hosts
- [ ] Slash prompts installed:

```bash
python3 openwebui/install_owui_prompts.py
```

- [ ] SSH / Postgres targets reachable when testing **access = yes**

**Expected:** Chat can select **auditor**; `/` shows prompts such as `/list-sessions`, `/list-status`, `/list-results`.

---

## 1. Smoke — chat connectivity

- [ ] New chat → model **auditor**
- [ ] Send a short message (e.g. `List audit sessions`) and get a non-empty reply
- [ ] Reply is not an auth error (401) or a silent hang
- [ ] `/list-sessions` returns a markdown table **or** a clear message that the warehouse is empty / disabled

**Expected:** Agent responds in chat; warehouse list path works without starting an audit.

---

## 2. Intake + preaudit scope (happy path)

- [ ] Send `Start an audit` (or `/start-it-audit`)
- [ ] Each pause shows `[AUDIT_INTAKE:…]` in the assistant message
- [ ] **Step 1:** answer with the lab **client name**
- [ ] **Step 2:** CMDB → answer **no** (inventory-only)
- [ ] **Step 3:** access → answer **yes**
- [ ] Wait for host discovery / probe (may take a while)
- [ ] **Step 4:** message includes a **host → frameworks** table
- [ ] Reply `confirm` (or `all` / `run all`)
- [ ] Intake completes; assessment starts (REQ progress / tool activity)
- [ ] Note the new warehouse session number (`#N`) via `/list-sessions` or chat text

**Expected:** After `confirm`, assessment runs for proposed host/framework jobs; a numbered session exists for the client.

---

## 3. Intake scope — exclude path

Use a **new** audit (or stop before confirming on a parallel chat).

- [ ] Reach step 4 with a host → frameworks table
- [ ] Reply with a garbage phrase (e.g. `asdf`) → agent **re-prompts**; assessment does **not** start
- [ ] Reply `exclude <framework_id>` (e.g. `exclude ubuntu_cis_24_l2`) **or**
      `exclude <ip>/<framework>` (e.g. `exclude 10.200.29.79/postgres_cis`)
- [ ] Assessment starts only for remaining jobs (excluded frameworks not assessed)

**Expected:** Invalid scope → re-ask. Valid exclude → trimmed plan runs.

---

## 4. Intake — no access fallback

- [ ] Start another audit for a test client
- [ ] Steps 1–2 as usual; **step 3** answer **no** (no access)
- [ ] Step 4 asks for **IT / Cybersecurity / both** (no live host table)
- [ ] Reply `IT` or `both`
- [ ] Some assessment / routing path still starts (NLP / fallback)

**Expected:** No-access path does not show host→framework table; domain pick still proceeds.

---

## 5. Live warehouse during assess

During a running audit (access = yes, after `confirm`):

- [ ] In another message (same or new chat): `/list-status` for client + session `#N`
- [ ] Table columns include Hostname, IP, Framework, Status like `N/M ready`
- [ ] Counts grow as more REQs finish (`15/60 ready` → higher numerator)
- [ ] `/list-results` for the same client/session shows REQ cells while status may still be `running`
- [ ] `/list-host <hostname-or-ip> <framework>` shows a REQ table for that host

**Expected:** Warehouse updates on the wire; list commands work mid-run.

---

## 6. HITL (if a requirement fails)

Skip this section if no failure/HITL appears.

- [ ] Failed REQ pauses with skip/retry guidance and `[AUDIT_HITL:…]`
- [ ] Reply `skip` **or** `retry`
- [ ] Graph resumes the **same** thread
- [ ] `/list-sessions` still shows the **same** session `#N` (no unexpected `#N+1`)

**Expected:** HITL does not allocate a new warehouse session number.

---

## 7. Finalize + artifacts

- [ ] Audit finishes with a report summary in chat
- [ ] ZIP / download link appears when archive is enabled
- [ ] On disk: `artifacts/<Client>/…` contains findings / `report.md` (and host segments if multi-host)
- [ ] `/list-sessions` shows session status `completed` (or completed after finalize)
- [ ] `/list-results` after finalize is consistent (one host/framework rollup; cells match report)

**Expected:** Artifacts on disk + completed warehouse session + list-results usable.

---

## 8. Sessions / continue

- [ ] Start an audit, reach assessment, then **cancel / disconnect** mid-run
- [ ] `/list-sessions` or `/sessions-continue` shows `interrupted` for that client
- [ ] `/continue-session` (or `continue session N for <Client>`) resumes work
- [ ] Session number stays **`#N`** (does **not** become `#N+1`)
- [ ] For a **completed** session: do **not** use `/continue*`; use `/list-results` or `/update-report` instead

**Expected:** Continue resumes the same warehouse session; completed sessions are list/report only.

---

## 9. Post-audit follow-up

Against a finished client with evidence on disk:

- [ ] `/gather-req` for a named REQ + framework + client (optional hint)
- [ ] `/refill-req` (or `/revise-req`) updates observation/recommendation
- [ ] `/update-report` rebuilds the Markdown report / ZIP
- [ ] `/list-results` (or `/list-host`) reflects updated cells

**Expected:** Follow-up writes into the same client artifacts; warehouse cells refresh.

---

## 10. Ad-hoc + Visualizer (optional smoke)

- [ ] If `ADHOC_COMMANDS_ENABLED=true`: `/run-command` with a harmless check  
      (e.g. `hostname` or `grep PermitRootLogin /etc/ssh/sshd_config`)
- [ ] Switch model to **Visualizer**; run `/dashboard` for the lab client
- [ ] Dashboard / chart content appears (Inline Visualizer configured)

**Expected:** Ad-hoc returns command output; Visualizer path does not break chat.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| 401 / empty models | Agent `API_KEY` vs Open WebUI connection key; connection URL `http://agent:8000/v1` |
| Wrong behavior / “new audit” | Model must be **auditor** (not Visualizer) for slash intents |
| No sessions / empty warehouse | `RESULTS_DB_ENABLED`, `results-db` healthy, admin DSN |
| No hosts at step 4 | Inventory path `inventory/<Client>/`, Credentials table, access = yes |
| Continue allocates new `#` | Prefer `continue session N for Client`; avoid starting a new audit phrase |
| Slash commands missing | Re-run `python3 openwebui/install_owui_prompts.py` |

---

## Sign-off

| Section | Pass? | Notes |
|---------|-------|-------|
| 0 Preconditions | | |
| 1 Smoke | | |
| 2 Intake happy path | | |
| 3 Exclude path | | |
| 4 No-access fallback | | |
| 5 Live warehouse | | |
| 6 HITL | | |
| 7 Finalize | | |
| 8 Continue | | |
| 9 Follow-up | | |
| 10 Optional | | |

**Overall:** Pass / Fail / Partial — `________________`

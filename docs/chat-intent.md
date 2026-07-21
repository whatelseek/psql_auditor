# Chat intent routing

Every Open WebUI message is classified **before** any LangGraph run starts.
Classification lives in [`src/auditor/intent.py`](../src/auditor/intent.py) and is
**regex-based** (no LLM): fast, deterministic, and safe for production.

This is **not** the pre-audit intake questionnaire. Intake only runs when the
intent is a **full audit**. See [`pre-audit-intake.md`](pre-audit-intake.md) for
the difference.

## Why intent exists

Without routing, phrases like “run this command” or “list sessions” would start
a full checklist audit. Intent picks one handler path:

| Intent | Handler | Typical phrases |
|--------|---------|-----------------|
| `audit` (default) | Full audit graph (+ intake when enabled) | `Start Ubuntu CIS audit`, `Проведи аудит` |
| `adhoc` | One-shot SSH/SQL/playbook tools | `Run this command: …`, `Execute SQL: …` |
| `revise_req` | Append evidence into an existing REQ folder | `Evaluate REQ-002`, `Revise REQ-001` |
| `refill_finding` | Rewrite observation/recommendation from disk | `Prepare new observation for REQ-001` |
| `update_report` | Rebuild `report.md` + ZIP from findings | `Update the report` |
| `list_sessions` | Results warehouse session table | `Which sessions need continue?` |

Ambiguous text falls through to **`audit`**.

## Pipeline position

```text
Open WebUI chat completion
        │
        ▼
  classify_intent(latest user message)     ← intent.py
        │
        ├─ list_sessions  → ResultsStore list
        ├─ revise_req     → followup gather (+ optional refill)
        ├─ refill_finding → followup cell rewrite
        ├─ update_report  → followup report rebuild
        ├─ adhoc          → adhoc executor (if ADHOC_COMMANDS_ENABLED)
        └─ audit          → intake (optional) → audit StateGraph
```

Entry points: [`src/auditor/api/openai_compat.py`](../src/auditor/api/openai_compat.py)
(`classify_intent` on both non-stream and SSE paths).

Pause markers (`[AUDIT_HITL:…]`, `[AUDIT_INTAKE:…]`, `[AUDIT_CONTINUE:…]`) are
resolved **before** or alongside intent so resumes are not misrouted as new audits.

## Intent vs intake vs HITL

| Module | Question it answers | When it runs |
|--------|---------------------|--------------|
| **Intent** | Which *feature* should handle this message? | Every chat turn |
| **Intake** | Client / CMDB / access / audit domain? | Only on `audit` when `INTAKE_ENABLED` |
| **HITL** | Skip or retry a failed REQ? | Mid-audit interrupt |

## Classification rules (summary)

Order matters (first strong match wins among the priority checks):

1. **List sessions** — session / continue warehouse phrases (EN + RU).
2. **Refill finding** — prepare/rewrite observation or recommendation.
3. **Update report** — regenerate / refresh the report.
4. **Playbook ad-hoc** — “execute/run the playbook commands for …” (even with a REQ id).
5. **Revise REQ** — REQ id + revise/evaluate/gather/re-check language.
6. **Ad-hoc** — run/execute command/SQL/SSH signals (and command payload markers).
7. Else → **`audit`**.

Helpers used elsewhere:

- `extract_req_ids(text)` → normalized `REQ-NNN` list
- `wants_full_revise(text)` → gather **and** refill in one step (`Revise REQ…`)

## Config

| Env | Effect |
|-----|--------|
| `ADHOC_COMMANDS_ENABLED` | When `false`, ad-hoc intent falls through to the audit path |
| `INTAKE_ENABLED` | Only affects the **audit** path after intent chooses it |
| `RESULTS_DB_ENABLED` | Required for useful `list_sessions` replies |

There is no separate “intent enabled” flag — routing is always on.

## Examples

| Message | Intent |
|---------|--------|
| `Start PostgreSQL CIS audit` | `audit` |
| `Run this command: \`uptime\`` | `adhoc` |
| `Run playbook commands for REQ-002 on Ubuntu` | `adhoc` |
| `Evaluate REQ-001 on ubuntu_cis_24_l2 for host 10.0.0.1` | `revise_req` |
| `Prepare new observation for REQ-001` | `refill_finding` |
| `Update the report` | `update_report` |
| `Which sessions need continue?` | `list_sessions` |
| `continue` / `[AUDIT_CONTINUE:…]` | Resume path (pause marker), not a new classify outcome |

## LLM alternative?

An LLM *could* classify intents (HITL already uses LLM when regex is unclear).
Chat routing stays regex on purpose: no extra latency/cost, reproducible tests,
and a safe default (`audit`) when unsure. A hybrid (regex first, LLM on low
confidence) is possible later; see module docstring in `intent.py`.

## Related

- Pre-audit questionnaire: [`pre-audit-intake.md`](pre-audit-intake.md)
- Ad-hoc commands: [`adhoc-commands.md`](adhoc-commands.md)
- Post-audit follow-up: [`post-audit-followup.md`](post-audit-followup.md)
- Results sessions: [`results-database.md`](results-database.md)
- Starting audits: [`starting-an-audit.md`](starting-an-audit.md)

# Pre-audit intake

Intake is the **three-step questionnaire** that runs at the start of a **full
audit** (when `INTAKE_ENABLED=true`). It collects scope and environment facts
before checklist assessment begins.

Implementation: [`src/auditor/intake.py`](../src/auditor/intake.py)  
Graph node: `intake_gate` on a small intake StateGraph (separate from the main
audit graph). See also [`chat-intent.md`](chat-intent.md) — intake is **not**
intent classification.

## Intent vs intake

| | Intent | Intake |
|--|--------|--------|
| File | `intent.py` | `intake.py` |
| Purpose | Route the chat message to a feature | Ask setup questions for a new audit |
| Runs when | Every message | Only after intent = `audit` |
| Output | `audit` / `adhoc` / `revise_req` / … | Client name, access, host→framework plan |
| Mechanism | Step 1 deterministic; steps 2–3 LLM JSON | LangGraph `interrupt()` + `[AUDIT_INTAKE:<thread>]` |

Ad-hoc commands, REQ revise/refill, report update, and session listing **skip**
intake entirely.

## Operator flow

```text
Intent = audit
      │
      ▼
intake_gate (may interrupt between steps)
  1. Client name          → artifacts/<Client>/ …
  2. Access to servers?   → probe SSH (+ Postgres MCP when configured)
  3. Scope plan           → confirm / exclude / include frameworks
                            (after exclude|include → show updated plan → confirm)
      │
      ▼
Main audit graph
  route_framework → load_framework → collect_host_facts
  → assess_parallel → … → finalize
```

Reply in the **same chat** after each question. The assistant message embeds:

```text
[AUDIT_INTAKE:<thread_id>]
```

so the next turn resumes the same intake (see HITL/continue marker pattern in
the README).

Disable with:

```env
INTAKE_ENABLED=false
```

When disabled, audits go straight to framework routing (chat/file/inventory
hints only).

## Steps in detail

### 1. Client name

- Becomes the evidence root: `artifacts/<ClientName>/`
- Used for results-warehouse session numbering (`results_<client_slug>`)
- Clear short names work best (EN or RU)
- Parsed deterministically (no LLM)

### 2. Access probe

Checks whether SSH (and Postgres MCP when credentials exist) can reach targets.
Failures are summarized in chat; the operator can still continue depending on
framework needs. Answer interpreted via LLM yes/no JSON.

### 3. Scope — host→framework plan

When inventory hosts are reachable, intake proposes a host→framework plan.

| Reply intent | Effect |
|--------------|--------|
| **Confirm** | Accept the **current** plan and start assessment |
| **Exclude** | Remove named frameworks / host pairs, then **re-show** the plan |
| **Include / only** | Keep only named frameworks / pairs, then **re-show** the plan |

After exclude or include, assessment does **not** start until the operator
explicitly **confirms** the updated plan (they may trim again first).

If no host plan is available, step 3 falls back to a free-form domain choice
(IT / cybersecurity / both) via `frameworks_for_audit_type()`.

## Parsing answers

- Step 1 (client name): deterministic parser
- Steps 2–3: LLM JSON interpretation only (no regex fallback on unclear replies)
- Prompts are localized (EN / RU) via `prompts_for_language`

## Markers and resume

| Marker | Meaning |
|--------|---------|
| `[AUDIT_INTAKE:<thread>]` | Continue the questionnaire |
| `[AUDIT_HITL:<thread>]` | Skip/retry a failed REQ (mid-audit) |
| `[AUDIT_CONTINUE:<thread>]` | Resume after disconnect mid-assess |

Newest pause marker in chat history wins when resolving resume.

## Config

| Env | Default | Role |
|-----|---------|------|
| `INTAKE_ENABLED` | `true` | Master switch for the questionnaire |
| `INVENTORY_DIR` | `inventory` | Working inventory (hosts + credentials) |
| SSH / PG | `secrets/connection.md` | Credentials (not Compose env for secrets) |

## Related

- Chat routing: [`chat-intent.md`](chat-intent.md)
- Starting an audit (operator guide): [`starting-an-audit.md`](starting-an-audit.md)
- Results sessions: [`results-database.md`](results-database.md)
- Russian manual: [`user-manual-ru.md`](user-manual-ru.md)

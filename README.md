# auditor

LangGraph security auditor. **You create frameworks** by dropping Markdown files into [`agents/`](agents/). The agent routes your chat request to a framework, fills a fixed report (Status / Observation / Recommendation), **writes command results under a folder per requirement**, **pauses for human-in-the-loop** when a check cannot be audited, and can **cycle to reconnect** if the MCP/SSH session dies.

**Руководство пользователя (RU):** [`docs/user-manual-ru.md`](docs/user-manual-ru.md) — развёртывание, использование, добавление Markdown-фреймворков.

## Create a framework

Add `agents/<name>.md`:

```markdown
---
id: ubuntu_cis
aliases: [ubuntu, linux, debian]
description: Ubuntu CIS host hardening
---
# Ubuntu CIS Benchmark

## REQ-001: SSH root login disabled
**Category:** Remote Access
**Severity:** Critical
**How to verify:** Read /etc/ssh/sshd_config PermitRootLogin
**Pass criteria:** PermitRootLogin no
```

No code changes required — new files are discovered from `AGENTS_DIR`.

Bundled examples: `postgres_cis`, `ubuntu_cis`, `windows_cis`.

## Graph (cyclic + HITL)

```
START → route_framework → load_framework → assess_parallel
                              ↑                    │
                              │                    ├─ session errors → reconnect_session ─┐
                              │                    │                                       │
                              │◄───────────────────┴───────────────────────────────────────┘
                              │                    │
                              │                    └─ failed REQs → human_gate (interrupt)
                              │                              │ skip / retry (chat reply)
                              │◄──── retry ──────────────────┤
                              │                              └─ no more failures → finalize → END
```

### Human-in-the-loop (Open WebUI)

Inspired by [Open WebUI ↔ LangGraph HITL pipes](https://pessini.medium.com/from-open-webui-to-langgraph-building-a-human-in-the-loop-pipe-for-real-time-ai-control-26561cca9f9c): the graph uses LangGraph ``interrupt()``; Open WebUI resumes on the next chat message.

When a requirement fails after automatic session retries, the agent replies with:

- which `REQ-*` could not be audited
- **why** (SSH/MCP/tool error)
- **recommendations**
- ask: **skip** / **retry** (or **skip all** / **retry all**)

Reply in the same chat. A marker `[AUDIT_HITL:<thread>]` ties the resume to the paused run. Set `HITL_ENABLED=false` to auto-finalize with `error` statuses instead.

During long audits Open WebUI streams **live tool calls** and phase/reasoning deltas (SSH/MCP). If the chat disconnects mid-run, reply **continue** (or use `[AUDIT_CONTINUE:<thread>]`) — checkpoints live under `CHECKPOINT_PATH` (default `artifacts/.checkpoints/auditor.sqlite`) and survive agent container restarts.

### Audit ZIP in chat

When the audit finishes, the agent:

1. Zips `artifacts/<client_name>/` (Markdown report + per-REQ command outputs)
2. Serves it at `/v1/downloads/<run_id>_audit.zip?token=…`
3. Uploads it to Open WebUI Files (when `OPEN_WEBUI_URL` is set)
4. Appends a **Download ZIP** link to the chat reply

Configure `PUBLIC_BASE_URL` (browser → agent) and `OPEN_WEBUI_URL` (agent → Open WebUI).

## Starting an audit (Open WebUI)

Operators start audits in Open WebUI. The agent runs a **pre-audit intake**
(client name → CMDB/NetBox → access probe → CIS / IT / both), then assesses.

→ **[`docs/starting-an-audit.md`](docs/starting-an-audit.md)**  
→ NetBox MCP: [`docs/netbox-mcp.md`](docs/netbox-mcp.md)  
→ Example target file: [`docs/examples/target.example.yaml`](docs/examples/target.example.yaml)  
→ Connection secrets: [`secrets/connection.example.md`](secrets/connection.example.md)

Short version:

1. Open WebUI → model `auditor`
2. Chat: `Start PostgreSQL CIS audit` (or IT audit / both)
3. Answer intake questions; agent probes NetBox / SSH / Postgres as applicable
4. Report + **Download ZIP** (includes host facts / INVENTORY.md when relevant)

Without a CMDB, scope comes from [`inventory/INVENTORY.md`](inventory/INVENTORY.example.md).
SSH/PG/NetBox credentials live only in [`secrets/connection.md`](secrets/connection.example.md).

### Long-term memory (command playbooks)

Procedural memory remembers **how to verify** each REQ (SSH/SQL recipes) per framework — [LangChain long-term memory](https://docs.langchain.com/oss/python/concepts/memory) style, not chat history.

- Seeds: [`agents/playbooks/*.yaml`](agents/playbooks/)
- Learned successes: `memory/learned_playbooks.json`
- Docs: [`docs/long-term-memory.md`](docs/long-term-memory.md)

### Chat examples

- `Run a PostgreSQL CIS audit`
- `Audit this Ubuntu host against CIS`
- `Windows Server CIS hardening check`
- `Conduct PostgreSQL and Ubuntu audit` → **two separate graphs**, merged report + ZIP

## Stack

- **LangGraph** orchestration + **LangChain** tools/models
- DB evidence: [langchain-mcp-adapters](https://github.com/langchain-ai/langchain-mcp-adapters) → [antonorlov/mcp-postgres-server](https://github.com/antonorlov/mcp-postgres-server)
- Host evidence: SSH (`ssh_run` / `ssh_read_file`)
- Models: LiteLLM · UI: Open WebUI (`/v1`)

## Quick start

```bash
cp .env.example .env
cp secrets/connection.example.md secrets/connection.md   # SSH/PG/MCP only here
docker compose up --build
# http://localhost:3000 → model auditor
```

## Fixed report cells

| From your `agents/*.md` | Filled by the model |
|-------------------------|---------------------|
| ID, Title, Category, Severity, Pass criteria | Status, Observation, Recommendation |

## Evidence on disk

Each audit creates:

```text
artifacts/<client_name>/
  meta.json
  report.md
  <framework_id>/
    REQ-001/
      requirement.json
      001_ssh_run.txt      # full command + stdout/stderr
      001_ssh_run.json
      002_mcp_query.txt
      finding.json
    REQ-002/
      ...
```

After intake, the folder is named after the **client** (e.g. `TestCompany`), not a timestamp.
Multi-framework runs (e.g. PostgreSQL + Ubuntu) share one `<run_id>` with a subfolder per framework. Configure root with `EVIDENCE_DIR` (default `artifacts`; Docker mounts `./artifacts`).

## CIS compliance charts (Open WebUI)

Bar charts of **compliance % by severity** (Overall / Critical / High / …):

- Open WebUI **Tool** + auto **Filter**: [`docs/cis-compliance-charts.md`](docs/cis-compliance-charts.md)
- Also appended in the agent report when `COMPLIANCE_CHARTS_IN_REPORT=true`

## Audit benchmark history

Every completed checklist audit appends aggregate scores to [`memory/benchmark.md`](memory/benchmark.md) (pass/fail/compliance % by framework). See [`docs/audit-benchmark.md`](docs/audit-benchmark.md).

## Ad-hoc commands (Open WebUI)

Ask the model to **run commands** without a full checklist audit:

```text
Run this command: `grep PermitRootLogin /etc/ssh/sshd_config`
Execute SQL: SELECT name, setting FROM pg_settings WHERE name = 'ssl'
```

See [`docs/adhoc-commands.md`](docs/adhoc-commands.md). Toggle with `ADHOC_COMMANDS_ENABLED`.

## Post-audit follow-up

After an audit, revise a requirement (new logs land in the same `REQ-*` folder) and rebuild the report:

```text
Revise REQ-002 on Ubuntu
Update the report from new evidence
```

See [`docs/post-audit-followup.md`](docs/post-audit-followup.md).

## Results PostgreSQL warehouse

Optionally dual-write filled checklist cells (status / observation / recommendation)
to a per-client Postgres database. Evidence files stay on disk. See
[`docs/results-database.md`](docs/results-database.md) (`RESULTS_DB_*`).

## Config

See [`.env.example`](.env.example): `AGENTS_DIR`, `PLAYBOOKS_DIR`, `MEMORY_*`, `EVIDENCE_DIR`, `HITL_ENABLED`, `ARCHIVE_ENABLED`, `COMPLIANCE_CHARTS_IN_REPORT`, `BENCHMARK_ENABLED`, `BENCHMARK_PATH`, `ADHOC_COMMANDS_ENABLED`, `RESULTS_DB_*`, `PUBLIC_BASE_URL`, `OPEN_WEBUI_*`, `MAX_SESSION_RETRIES`, `MAX_PARALLEL_ASSESSMENTS`, `LITELLM_*`, `PG_*`, `SSH_*`, `MCP_POSTGRES_*`.

MCP architecture: [`docs/langchain-mcp.md`](docs/langchain-mcp.md).

## Development

```bash
pip install -e ".[dev]"
pytest
```

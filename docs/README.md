# Documentation index

Operator and developer docs for **auditor** (`psql_auditor`).

## Start here

| Doc | Topic |
|-----|--------|
| [Starting an audit](starting-an-audit.md) | Open WebUI operator flow, target files, security |
| [Chat intent](chat-intent.md) | How messages are routed (audit / ad-hoc / follow-up / sessions) |
| [Pre-audit intake](pre-audit-intake.md) | Client / CMDB / access / domain questionnaire |
| [User manual (RU)](user-manual-ru.md) | Развёртывание и использование на русском |

## Features

| Doc | Topic |
|-----|--------|
| [Ad-hoc commands](adhoc-commands.md) | Run SSH/SQL/playbook without a full audit |
| [Post-audit follow-up](post-audit-followup.md) | Evaluate / refill / update report |
| [Results database](results-database.md) | Postgres warehouse + numbered sessions |
| [Long-term memory](long-term-memory.md) | Procedural playbooks (not chat history) |
| [CIS compliance charts](cis-compliance-charts.md) | Open WebUI % bar charts |
| [CIS audit import](cis-audit-import.md) | Convert Nessus/CIS `.audit` → Markdown |

## Integrations

| Doc | Topic |
|-----|--------|
| [LangChain MCP](langchain-mcp.md) | Postgres MCP pool / read-only SQL |

## Architecture snapshot

```text
Open WebUI ──► /v1 chat ──► intent router
                                │
           ┌────────────────────┼────────────────────┐
           ▼                    ▼                    ▼
        ad-hoc /            full audit            list sessions
        follow-up              │                  (results DB)
                               ▼
                            intake (optional)
                               ▼
                     LangGraph audit StateGraph
                     (route → load → host facts →
                      assess ⇄ reconnect / HITL → finalize)
```

Graph visualization can be regenerated from `AuditorGraph.graph.get_graph()`
(Mermaid / PNG). Node list: `route_framework`, `load_framework`,
`collect_host_facts`, `assess_parallel`, `reconnect_session`, `human_gate`,
`finalize`.

## Ports (Docker Compose defaults)

| Service | Host | Container |
|---------|------|-----------|
| Open WebUI | `3001` (`WEBUI_HOST_PORT`) | `8080` |
| Agent | `8001` (`AGENT_HOST_PORT`) | `8000` |
| LiteLLM (profile `local-llm`) | `4000` | `4000` |

Override via `.env`. See root [`README.md`](../README.md) and
[`.env.example`](../.env.example).

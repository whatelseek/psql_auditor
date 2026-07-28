---
name: stack
description: Runtime and library stack for the Infrastructure Auditor.
triggers:
  - "stack"
  - "python"
  - "langgraph"
  - "fastapi"
  - "postgres"
  - "node"
edges:
  - target: context/setup.md
    condition: for install commands
  - target: context/architecture.md
    condition: for how stack pieces connect
grounds_to: []
last_updated: 2026-07-28
---

# Stack

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | Python 3 (project venv) | `src/` layout, packaging via project config |
| Orchestration | LangGraph + LangChain tools | Checkpoints AsyncSqliteSaver / memory |
| API | FastAPI OpenAI-compatible + inventory routes | `src/auditor/api/` |
| CLI | `psql-auditor` | Typer/click-style entry in `cli.py` |
| Data | PostgreSQL (results warehouse / tests) | Optional; fixtures may use local Docker PG |
| Remote exec | SSH (Paramiko path), WinRM | Via Tool Registry adapters |
| MCP | stdio/HTTP MCP clients | `mcp_registry` + Postgres MCP tools |
| Frameworks | Markdown in `agents/` | FrameworkRegistry |
| Architectural memory | **mex-agent 0.7.0** (pinned in `package.json`) | Local npm install only |
| Node | >= 20 for MEX CLI | Not used for auditor runtime |

LLM providers are configured via settings/env — never hard-code keys in repo.

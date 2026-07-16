# psql_auditor

LangGraph PostgreSQL security auditor. The agent walks a Markdown checklist **one requirement at a time**, gathers evidence with **SSH** and **PostgreSQL/MCP** tools, calls models through **LiteLLM**, and exposes an **OpenAI-compatible API** for **Open WebUI**.

## Architecture

```
Open WebUI  →  Agent API (/v1/chat/completions)  →  LangGraph
                      │                                │
                      │                                ├─ SSH tools
                      │                                ├─ SQL / MCP tools
                      │                                └─ checklist MD
                      └─ LiteLLM (model gateway)
```

## Quick start

1. Copy env and set at least a model provider key:

```bash
cp .env.example .env
# set OPENAI_API_KEY, and optionally SSH_* / DATABASE_URL
```

2. Start the stack:

```bash
docker compose up --build
```

3. Open WebUI at [http://localhost:3000](http://localhost:3000). Select model **`psql-auditor`** (or add connection `http://agent:8000/v1` with API key `sk-auditor-local` if not pre-wired).

4. Ask: `Run a full PostgreSQL security audit against the configured host.`

### Local API (without Compose UI)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn psql_auditor.api.app:app --host 0.0.0.0 --port 8000
```

LiteLLM should be reachable at `LITELLM_BASE_URL` (default `http://localhost:4000`).

```bash
curl -s http://localhost:8000/v1/models \
  -H "Authorization: Bearer sk-auditor-local"

curl -s http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-auditor-local" \
  -H "Content-Type: application/json" \
  -d '{"model":"psql-auditor","messages":[{"role":"user","content":"Audit PostgreSQL now"}],"stream":false}'
```

## Checklist

Requirements live in [`checklists/postgres_cis.md`](checklists/postgres_cis.md). Each item:

```markdown
## REQ-001: Title
**Category:** ...
**Severity:** ...
**How to verify:** ...
**Pass criteria:** ...
```

Replace or extend the file; the agent reloads it on each audit run (`CHECKLIST_PATH`).

## Tools

| Tool | Purpose |
|------|---------|
| `ssh_run` / `ssh_read_file` | Host config, packages, ports, file perms |
| `run_sql` | Read-only `SHOW` / `SELECT` against `DATABASE_URL` |
| `mcp_call_tool` / `mcp_list_tools` | Optional Postgres MCP server |

Configure via `.env` (`SSH_*`, `DATABASE_URL` or `PG_*`, `MCP_POSTGRES_URL` or `MCP_POSTGRES_COMMAND`).

For SSH keys in Compose, place the key under `./.keys` (or set `SSH_KEY_HOST_PATH`) and set `SSH_PRIVATE_KEY_PATH=/keys/id_rsa`.

## Configuration

See [`.env.example`](.env.example). Important knobs:

- `LITELLM_BASE_URL` / `LITELLM_MODEL` / `LITELLM_API_KEY` — model gateway
- `API_KEY` — optional Bearer gate for `/v1`
- `CHECKLIST_PATH` — Markdown checklist
- Target access: `SSH_*`, `DATABASE_URL`, `MCP_*`

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT

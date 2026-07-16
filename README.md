# psql_auditor

LangGraph PostgreSQL security auditor. The agent walks a Markdown checklist **one requirement at a time**, gathers evidence with **SSH** and **PostgreSQL MCP** ([antonorlov/mcp-postgres-server](https://github.com/antonorlov/mcp-postgres-server)), calls models through **LiteLLM**, and exposes an **OpenAI-compatible API** for **Open WebUI**.

## Architecture

```
Open WebUI  →  Agent API (/v1/chat/completions)  →  LangGraph
                      │                                │
                      │                                ├─ SSH tools
                      │                                ├─ MCP Postgres (npx mcp-postgres-server)
                      │                                └─ checklist MD
                      └─ LiteLLM (model gateway)
```

**Database queries always go through MCP** (`mcp_query`, catalog helpers). Direct SQL is not bound into the agent.

## Quick start

1. Copy env and set provider + Postgres credentials:

```bash
cp .env.example .env
# set OPENAI_API_KEY
# set PG_HOST / PG_USER / PG_PASSWORD / PG_DATABASE  (or DATABASE_URL)
# optional: SSH_* for host checks
```

2. Start the stack (agent image includes Node.js for `npx`):

```bash
docker compose up --build
```

3. Open WebUI at [http://localhost:3000](http://localhost:3000). Select model **`psql-auditor`**.

4. Ask: `Run a full PostgreSQL security audit against the configured host.`

### Local API (without Compose UI)

Requires Node.js so `npx -y mcp-postgres-server` can run.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn psql_auditor.api.app:app --host 0.0.0.0 --port 8000
```

## Postgres MCP ([antonorlov/mcp-postgres-server](https://github.com/antonorlov/mcp-postgres-server))

Defaults in `.env` / Compose:

```bash
MCP_POSTGRES_COMMAND=npx
MCP_POSTGRES_ARGS=-y mcp-postgres-server
PG_HOST=...
PG_PORT=5432
PG_USER=...
PG_PASSWORD=...
PG_DATABASE=...
```

The agent keeps a persistent stdio MCP session and passes `PG_*` into the subprocess. Agent tools:

| Tool | MCP tool | Purpose |
|------|----------|---------|
| `mcp_query` | `query` | SELECT evidence (`SHOW` auto-rewritten to `pg_settings`) |
| `mcp_list_schemas` | `list_schemas` | List schemas |
| `mcp_list_tables` | `list_tables` | List tables |
| `mcp_describe_table` | `describe_table` | Table structure |
| `mcp_connect_db` | `connect_db` | Explicit connect (usually unused if `PG_*` set) |

Mutating MCP `execute` is **not** exposed.

## Tools (host)

| Tool | Purpose |
|------|---------|
| `ssh_run` / `ssh_read_file` | Host config, packages, ports, file perms |

For SSH keys in Compose, place the key under `./.keys` and set `SSH_PRIVATE_KEY_PATH=/keys/id_rsa`.

## Checklist

Requirements live in [`checklists/postgres_cis.md`](checklists/postgres_cis.md). Each item:

```markdown
## REQ-001: Title
**Category:** ...
**Severity:** ...
**How to verify:** ...
**Pass criteria:** ...
```

## Configuration

See [`.env.example`](.env.example):

- `LITELLM_*` — model gateway
- `API_KEY` — optional Bearer gate for `/v1`
- `PG_*` / `DATABASE_URL` — credentials for MCP Postgres
- `MCP_POSTGRES_COMMAND` / `MCP_POSTGRES_ARGS` — MCP launcher
- `SSH_*` — host checks

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT

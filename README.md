# psql_auditor

LangGraph security auditor. **You create frameworks** by dropping Markdown files into [`agents/`](agents/). The agent routes your chat request to a framework, fills a fixed report (Status / Observation / Recommendation), **writes command results under a folder per requirement**, and can **cycle to reconnect** if the MCP/SSH session dies.

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

## Graph (cyclic)

```
START → route_framework → load_framework → assess_parallel
                              ↑                    │
                              └── reconnect_session ┘  (session errors & retries left)
                                                   ↓
                                              finalize → END
```

## Chat examples (Open WebUI)

- `Run a PostgreSQL CIS audit`
- `Audit this Ubuntu host against CIS`
- `Windows Server CIS hardening check`
- `Conduct PostgreSQL and Ubuntu audit` → **two separate graphs in parallel**, merged report

## Stack

- **LangGraph** orchestration + **LangChain** tools/models
- DB evidence: [antonorlov/mcp-postgres-server](https://github.com/antonorlov/mcp-postgres-server)
- Host evidence: SSH (`ssh_run` / `ssh_read_file`)
- Models: LiteLLM · UI: Open WebUI (`/v1`)

## Quick start

```bash
cp .env.example .env   # OPENAI_API_KEY, PG_*, SSH_*
docker compose up --build
# http://localhost:3000 → model psql-auditor
```

## Fixed report cells

| From your `agents/*.md` | Filled by the model |
|-------------------------|---------------------|
| ID, Title, Category, Severity, Pass criteria | Status, Observation, Recommendation |

## Evidence on disk

Each audit creates:

```text
artifacts/<run_id>/
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

Multi-framework runs (e.g. PostgreSQL + Ubuntu) share one `<run_id>` with a subfolder per framework. Configure root with `EVIDENCE_DIR` (default `artifacts`; Docker mounts `./artifacts`).

## Config

See [`.env.example`](.env.example): `AGENTS_DIR`, `EVIDENCE_DIR`, `MAX_SESSION_RETRIES`, `MAX_PARALLEL_ASSESSMENTS`, `LITELLM_*`, `PG_*`, `SSH_*`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

# Starting an audit (Open WebUI)

This document describes how an operator starts a security audit with **auditor** through Open WebUI: attach a **target file** (host, credentials, description), then ask the agent to run one or more frameworks.

## Operator flow

```text
Open WebUI chat (model: auditor)
  │
  ├─ 1. Attach target file (YAML / JSON preferred)
  ├─ 2. Message: which frameworks to run
  │      e.g. "Start PostgreSQL and Ubuntu CIS audit"
  │
  ▼
Agent
  ├─ Parse target (hostname/IP, SSH, Postgres, description)
  ├─ Confirm target summary (secrets redacted)
  ├─ Apply credentials for this run only
  ├─ Route frameworks (from chat and/or file)
  ├─ Assess (HITL skip/retry on failures)
  └─ Finalize → ZIP report+evidence → Download link in chat
```

### Step-by-step

1. Open [Open WebUI](http://localhost:3000) and select model **`auditor`**.
2. Attach a target file (see [Target file format](#target-file-format)).
3. Send a clear start request naming the frameworks, for example:
   - `Start PostgreSQL CIS audit on this host`
   - `Audit Ubuntu CIS using the attached target`
   - `Conduct PostgreSQL and Ubuntu audit` → separate graphs per framework, one combined report/ZIP
4. Review the agent’s confirmation (host, OS/DB hints, frameworks). Secrets are never echoed in full.
5. If something is missing (e.g. no SSH password/key), reply with the missing data or **skip** / **retry** when HITL prompts appear during the run.
6. When finished, download the **audit ZIP** from the chat reply (report + per-requirement command outputs).

## Target file format

Prefer **YAML** or **JSON**. Plain text can work if Open WebUI injects the full file into the chat context, but structured files are more reliable for credentials.

### Minimal YAML example

```yaml
host:
  hostname: db-01.example.com   # or IP address
  description: "Prod Postgres 16 on Ubuntu 22.04 (DC1)"
  os: ubuntu                    # optional routing hint: ubuntu | windows | …

ssh:
  user: auditor
  port: 22
  # Use one of:
  password: "changeme"
  # private_key: |
  #   -----BEGIN OPENSSH PRIVATE KEY-----
  #   ...
  #   -----END OPENSSH PRIVATE KEY-----
  # private_key_path: /keys/id_ed25519   # path inside the agent container

postgres:
  # Defaults to host.hostname when omitted
  host: db-01.example.com
  port: 5432
  user: postgres
  password: "changeme"
  database: postgres

# Optional — otherwise inferred from the chat message
frameworks:
  - postgres_cis
  - ubuntu_cis
```

A copy of this template lives at [`examples/target.example.yaml`](examples/target.example.yaml).

### JSON equivalent

```json
{
  "host": {
    "hostname": "10.0.0.15",
    "description": "Lab Ubuntu + Postgres",
    "os": "ubuntu"
  },
  "ssh": {
    "user": "auditor",
    "port": 22,
    "password": "changeme"
  },
  "postgres": {
    "host": "10.0.0.15",
    "port": 5432,
    "user": "postgres",
    "password": "changeme",
    "database": "postgres"
  },
  "frameworks": ["postgres_cis", "ubuntu_cis"]
}
```

### Field reference

| Section | Field | Required | Notes |
|---------|--------|----------|--------|
| `host` | `hostname` | yes | DNS name or IP used for SSH (and default DB host) |
| `host` | `description` | recommended | Free text for context / report meta |
| `host` | `os` | no | Helps framework routing (`ubuntu`, `windows`, …) |
| `ssh` | `user` | for host checks | SSH username |
| `ssh` | `port` | no | Default `22` |
| `ssh` | `password` / `private_key` / `private_key_path` | one | Prefer keys over passwords |
| `postgres` | `host`/`port`/`user`/`password`/`database` | for DB checks | Used by antonorlov MCP (`PG_*`) |
| `frameworks` | list of ids | no | e.g. `postgres_cis`, `ubuntu_cis`, `windows_cis` |

Framework ids match drop-in files under [`agents/`](../agents/) (filename stem or YAML frontmatter `id`).

## Open WebUI settings (file content)

Open WebUI normally processes attachments with RAG. For target files that contain **credentials and a short structured document**, configure the `auditor` model so the **full file** reaches the agent:

- Prefer **Bypass Embedding and Retrieval** (or equivalent “full file context”) for this model / chat, **or**
- Ensure **File Context** injects the entire small target file into the prompt (not sparse RAG chunks).

Large unrelated documents are not required; keep the target file small and focused.

Optional advanced path: the agent may also fetch file bytes from Open WebUI’s Files API when `OPEN_WEBUI_URL` is set and the chat request includes file ids.

## How the agent uses the target

1. **Parse** — Read attached / injected target; merge with the latest user message.
2. **Route** — Choose framework(s) from `frameworks:` and/or phrases in the chat (`PostgreSQL`, `Ubuntu`, …).
3. **Bind credentials (run-scoped)** — SSH and Postgres settings from the file apply to **this audit thread/run only**. They do not permanently rewrite the container `.env`.
4. **Assess** — Checklist REQs run with SSH and/or MCP tools; evidence lands under `artifacts/<run_id>/…`.
5. **HITL** — On hard failures, ask skip / retry in chat (see [README](../README.md#human-in-the-loop-open-webui)).
6. **Deliver** — Final chat message includes the report summary and a **Download ZIP** link.

### Fallback without a file

If no target file is attached, the agent can still run using environment defaults (`SSH_*`, `PG_*` / `DATABASE_URL` in `.env`). That mode is suited to a single lab host wired in Compose, not multi-tenant targeting.

## Chat message examples

| User message | Expected routing |
|--------------|------------------|
| `Start audit using the attached target` | Frameworks from file, or default/postgres if unspecified |
| `Run PostgreSQL CIS on this host` | `postgres_cis` |
| `Ubuntu CIS only` | `ubuntu_cis` |
| `PostgreSQL and Ubuntu CIS please` | `postgres_cis` + `ubuntu_cis` (separate graphs) |
| `Windows Server hardening check` | `windows_cis` |

## Security practices

- **Do not** paste production passwords into chat text if you can attach a file and keep File Context restricted to trusted operators.
- The agent must **not** repeat passwords or private keys in confirmation or report cells; show `hostname`, `user`, and masked secrets only.
- Prefer **SSH private keys** mounted into the agent (`SSH_PRIVATE_KEY_PATH` / `private_key_path`) over passwords.
- Audit ZIP contents should keep a **redacted** target summary by default; raw secret material must not be copied into downloadable archives unless explicitly configured.
- Treat Open WebUI, LiteLLM, and chat logs as sensitive when target files contain credentials.

## Related

- Framework drop-ins: [`agents/`](../agents/)
- Evidence layout & ZIP delivery: [README — Evidence on disk](../README.md#evidence-on-disk)
- Config keys: [`.env.example`](../.env.example) (`OPEN_WEBUI_*`, `PUBLIC_BASE_URL`, `SSH_*`, `PG_*`, …)

# Starting an audit (Open WebUI)

This document describes how an operator starts a security audit with **auditor**
through Open WebUI. Full audits begin with a **pre-audit intake** questionnaire,
then discover each inventory host and run matching **IT** and/or **Cybersecurity**
frameworks.

## Operator flow

```text
Open WebUI chat (model: auditor)
  │
  ├─ 1. Message: start an audit (optional: attach target file)
  │
  ▼
Agent — intake (chat Q&A, marker [AUDIT_INTAKE:…])
  ├─ Client name
  ├─ Has CMDB / NetBox?
  │     ├─ yes → probe NetBox MCP
  │     └─ no  → inventory only (never call NetBox)
  ├─ Access to servers/services?
  │     ├─ yes → probe SSH + Postgres MCP, discover inventory hosts,
  │     │         propose host → frameworks plan
  │     └─ no  → no live host plan
  └─ Scope (step 4)
        ├─ with plan → confirm all, or exclude frameworks / host-fw pairs
        └─ without plan → IT / Cybersecurity / both (legacy domain pick)
  │
  ▼
Agent — assessment
  ├─ Run selected (host, framework) jobs under artifacts/<Client>/<host>/…
  └─ Finalize → combined report.md + ZIP
```

Disable intake with `INTAKE_ENABLED=false` (Compose / `.env`).

### Step-by-step

1. Open Open WebUI and select model **`auditor`**.
2. Send a start request, for example:
   - `Start an audit`
   - `Run IT audit`
   - `Conduct cybersecurity audit`
3. Answer intake questions (client name → CMDB → access → **confirm/exclude frameworks**).
4. If HITL prompts appear during the run, reply **skip** / **retry**.
5. Download the **audit ZIP** from the chat reply.

After access = **yes**, the agent pre-scans inventory hosts and shows a
**host → frameworks** table. Reply `confirm` (or `all`) to run everything, or
`exclude ubuntu_cis_24_l2, postgres_cis` / `exclude 10.0.0.1/ubuntu_cis_24_l2`
to trim scope before assessment starts.

When CMDB = **no**, the agent uses **inventory only** (no NetBox tools). Host list
and credentials come from the client `INVENTORY.md` credentials table.

NetBox credentials (only when CMDB = yes): [`secrets/connection.md`](../secrets/connection.example.md)
(`NETBOX_URL`, `NETBOX_TOKEN`). See [`netbox-mcp.md`](netbox-mcp.md).

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
  - ubuntu_cis_24_l2
  - it_audit
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
  "frameworks": ["postgres_cis", "ubuntu_cis_24_l2"]
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
| `frameworks` | list of ids | no | e.g. `postgres_cis`, `ubuntu_cis_24_l2`, `it_audit` |

Framework ids match drop-in files under [`agents/`](../agents/) (filename stem or YAML frontmatter `id`).

## Open WebUI settings (file content)

Open WebUI normally processes attachments with RAG. For target files that contain **credentials and a short structured document**, configure the `auditor` model so the **full file** reaches the agent:

- Prefer **Bypass Embedding and Retrieval** (or equivalent “full file context”) for this model / chat, **or**
- Ensure **File Context** injects the entire small target file into the prompt (not sparse RAG chunks).

Large unrelated documents are not required; keep the target file small and focused.

Optional advanced path: the agent may also fetch file bytes from Open WebUI’s Files API when `OPEN_WEBUI_URL` is set and the chat request includes file ids.

## How the agent uses the target

1. **Parse** — Read attached / injected target; merge with the latest user message.
2. **Discover hosts** — After intake, SSH every inventory host; match frameworks via
   `domain` + `detect` frontmatter on `agents/*.md` (filtered by IT / Cybersecurity / both).
3. **Bind credentials (run-scoped)** — Per-host SSH from inventory; Postgres from the PG row.
4. **Assess** — Checklist REQs run with SSH and/or MCP tools; evidence under
   `artifacts/<client_name>/<host>/…`.
5. **HITL** — On hard failures, ask skip / retry in chat (see [README](../README.md#human-in-the-loop-open-webui)).
6. **Deliver** — Final chat message includes the report summary and a **Download ZIP** link.

### Fallback without a file

If no target file is attached, the agent uses credentials from
[`secrets/connection.md`](../secrets/connection.example.md) (mounted into the
container). Those keys must not appear in `docker-compose.yml`.

## Chat message examples

| User message | Expected routing |
|--------------|------------------|
| `Start audit using the attached target` | Frameworks from file, or default/postgres if unspecified |
| `Run PostgreSQL CIS on this host` | `postgres_cis` |
| `Ubuntu CIS only` | `ubuntu_cis_24_l2` |
| `PostgreSQL and Ubuntu CIS please` | `postgres_cis` + `ubuntu_cis_24_l2` (separate graphs) |
| `IT inventory baseline` | `it_audit` |

## Security practices

- **Do not** paste production passwords into chat text if you can attach a file and keep File Context restricted to trusted operators.
- The agent must **not** repeat passwords or private keys in confirmation or report cells; show `hostname`, `user`, and masked secrets only.
- Prefer **SSH private keys** mounted into the agent (`SSH_PRIVATE_KEY_PATH` / `private_key_path`) over passwords.
- Audit ZIP contents should keep a **redacted** target summary by default; raw secret material must not be copied into downloadable archives unless explicitly configured.
- Treat Open WebUI, LiteLLM, and chat logs as sensitive when target files contain credentials.

## Related

- Framework drop-ins: [`agents/`](../agents/)
- Import CIS Nessus `.audit`: [`cis-audit-import.md`](cis-audit-import.md) (`ubuntu_cis_24_l2`)
- Evidence layout & ZIP delivery: [README — Evidence on disk](../README.md#evidence-on-disk)
- Config keys: [`.env.example`](../.env.example) (`OPEN_WEBUI_*`, `PUBLIC_BASE_URL`, `SSH_*`, `PG_*`, …)

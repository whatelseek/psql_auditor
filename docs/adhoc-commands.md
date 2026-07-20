# Ad-hoc audit commands

Run **SSH / SQL / playbook** commands from Open WebUI chat **without** starting a full CIS checklist audit.

## When this path is used

The chat API classifies the latest user message:

| Intent | Examples | Behavior |
|--------|----------|----------|
| **Ad-hoc** | `Run this command: \`uptime\``, `Execute SQL: SELECT …`, `Run playbook commands for REQ-002 on Ubuntu` | Tools only → Markdown results |
| **Audit** (default) | `Start Ubuntu CIS audit` | Full framework checklist (unchanged) |

Disable with:

```env
ADHOC_COMMANDS_ENABLED=false
```

## Modes

### 1) Freeform

Ask in natural language (EN or RU). The model maps the request to `ssh_run` / `ssh_read_file` / `mcp_query` and returns results.

```text
Run this command: `grep PermitRootLogin /etc/ssh/sshd_config`
Выполни команду `systemctl status ssh`
Execute SQL: SELECT name, setting FROM pg_settings WHERE name = 'ssl'
```

### 2) Playbook / REQ

Name a requirement (and framework). Seed or learned playbook tools run **deterministically**, then a short summary is written:

```text
Run playbook commands for REQ-002 on Ubuntu
Execute commands for REQ-001 postgres
```

Artifacts land under `artifacts/<run_id>/…` like a normal audit evidence folder (`adhoc` framework label when no checklist is loaded).

## Safety

- MCP stays **read-only** (`SELECT` / `SHOW`).
- SSH can run arbitrary remote commands — same trust model as full audits (env credentials).
- Prefer explicit phrasing so intent classification does not start a full audit by mistake.

## Related

- Playbooks / memory: [`long-term-memory.md`](long-term-memory.md)
- Starting full audits: [`starting-an-audit.md`](starting-an-audit.md)

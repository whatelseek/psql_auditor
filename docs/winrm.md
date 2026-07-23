# WinRM (Windows hosts)

Windows hosts are reached with **WinRM** (`pywinrm`) when inventory has a
**WinRM** Access row. Linux/Ubuntu keep using SSH. OpenSSH on Windows still
works via a normal **SSH** row.

## Inventory

```markdown
| Access | Host | Port | Username | Password / Token | Extra |
|--------|------|------|----------|------------------|-------|
| WinRM | 10.0.0.20 | 5985 | Administrator | … | transport=ntlm |
| WinRM | 10.0.0.21 | 5986 | Administrator | … | transport=ntlm |
```

| Port | Meaning |
|------|---------|
| `5985` | HTTP WinRM (default) |
| `5986` | HTTPS (sets `WINRM_USE_SSL` automatically) |

Extra cell options: `transport=ntlm|basic|credssp`, `use_ssl=true|false`,
`verify_ssl=true|false` (lab self-signed: `verify_ssl=false`).

Credentials become `WINRM_*` env / run-scoped overlays — not Compose.

## Tools

| Tool | Role |
|------|------|
| `winrm_run` | PowerShell script on the target |
| `winrm_read_file` | Read a Windows file (truncated) |

Bound into the assess / host_facts models together with SSH and Postgres MCP.
Intake access probe runs a short PowerShell hostname check when `WINRM_HOST`
is set.

## Frameworks

Add a Windows checklist under `agents/` with `detect.os_ids: [windows]` (none
ships by default). Discovery uses the same host→framework plan as Linux; for
WinRM-only hosts the inventory **WinRM** row is enough to appear as a target.

## Settings (optional overrides)

`WINRM_HOST`, `WINRM_PORT`, `WINRM_USER`, `WINRM_PASSWORD`, `WINRM_TRANSPORT`,
`WINRM_USE_SSL`, `WINRM_VERIFY_SSL`, `WINRM_COMMAND_TIMEOUT` — normally filled
from inventory, not `docker-compose.yml`.

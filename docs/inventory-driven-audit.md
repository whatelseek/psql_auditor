# Inventory-driven infrastructure audit launch

This document describes the inventory → validate → discovery → reconcile →
plan → confirm → execute workflow (INPUT-003 / INPUT-005).

Related checklist items: `INPUT-001` (open — acceptance candidate
[`5286a4d`](https://github.com/whatelseek/psql_auditor/commit/5286a4d773f62d0bc796b205ddd18994bdfc89af)),
`INPUT-003` (partial), `INPUT-005` (partial — production discovery wired;
independent acceptance still required), `CORE-006` (partial until
independent acceptance).

## Operator flow

```text
Create inventory/<ClientName>/
  ├─ INVENTORY.md | .yaml | .json
  ├─ CREDENTIALS.md          (optional dedicated credentials table)
  ├─ credentials.md / connection.md
  └─ QUESTIONNAIRE.md / questionnaires/ / EXCEPTIONS.md / NETWORK.md
        │
        ▼
psql-auditor inventory validate <ClientName>
psql-auditor inventory analyze <ClientName>
        │  production SSH/WinRM discovery by default
        │  reconcile discovered facts (never overwrite inventory facts)
        │  persist preflight revision + sanitized evidence
        ▼
psql-auditor audit plan <ClientName>
        │  shows detected assets + selected frameworks
        │  does NOT start execution
        ▼
psql-auditor audit start <ClientName> --confirm
        │  loads confirmed plan (does not re-run discovery)
        │  rejects plan_stale if inventory or discovery facts changed
        │  builds AuditRequest (with inventory version/hash)
        ▼
arun_request → audit_run_id
```

Client names must match `^[A-Za-z0-9_]+$` (Latin letters, digits, underscore).
Example directory: `inventory/Testcompany/`.

## Minimum inventory format

At least one in-scope host with:

| Field | Required | Notes |
|-------|----------|--------|
| Host id | yes | Stable asset id |
| IP / DNS | yes | Used for connection + credential match |
| Access | yes | `SSH` or `WinRM` |
| Port | recommended | Default 22 / 5985 |
| OS | optional | Missing OS → `needs_discovery` |
| Services | optional | Declared PostgreSQL is confirmed |

### Credentials (`CREDENTIALS.md` / inventory table)

Runtime credentials are resolved from, in order:

1. `INVENTORY.md`
2. `CREDENTIALS.md`
3. `credentials.md`
4. `connection.md`

Columns:

`Access | Host / URL | Port | Username | Password / Token | Database`

Or secret-free:

`Access | Host / URL | Port | Username | Secret Reference | Database`

Plaintext secrets are resolved **only at runtime** for live discovery / tool
calls. They are never persisted in `ClientInventory`, `AuditPlan`,
`AuditRequest`, API responses, logs, discovery evidence, or stored execution
artifacts — only `secret_ref` / `has_secret`.

## Discovery workflow (INPUT-005)

`inventory analyze` and `audit plan --refresh` use the production
`CompositeDiscoveryCollector` by default (`SshDiscoveryCollector` +
`WinrmDiscoveryCollector`).

Disable discovery explicitly:

```bash
psql-auditor inventory analyze <Client> --no-discovery
psql-auditor audit plan <Client> --refresh --no-discovery
```

API:

```json
POST /clients/{client_id}/inventory/analyze
{ "discovery": false }
```

Discovery is **enabled by default**. `audit start --confirm` does **not**
re-run discovery. To re-check after confirmation:

```bash
psql-auditor audit start <Client> --confirm --refresh-discovery
```

If effective discovery facts changed, the plan is rejected as `plan_stale`.

### SSH read-only commands (Linux/Unix)

```text
hostname
cat /etc/os-release
uname -a
ss -lntup || netstat -lntup
systemctl list-units --type=service --state=running --no-pager
command -v psql
command -v postgres
ps -ef
ps -ef | grep '[p]ostgres'
systemctl list-units --type=service --all | grep -i postgres
dpkg-query -W | grep -i postgres || rpm -qa | grep -i postgres
```

Never used: `sudo`, package install, config changes, service restarts, file
modification, or destructive commands.

### WinRM read-only commands (Windows)

```text
Get-CimInstance Win32_OperatingSystem
$env:COMPUTERNAME
Get-Service
Get-NetTCPConnection -State Listen
Get-Process
Get-CimInstance Win32_Product
```

Never modifies services, registry, firewall, local policies, or system config.

### Collected facts

hostname, os_name, os_family, os_version, running_services, listening_ports,
installed PostgreSQL packages, PostgreSQL processes/services, connection
transport. Each discovered fact carries:

`source=discovered`, `collector=ssh|winrm`, `confidence=high|medium|low`,
`evidence_ref`, `collected_at`.

### PostgreSQL confirmation rules

Confirmed only with strong evidence:

* running PostgreSQL process; or
* PostgreSQL system service; or
* installed package/binary **plus** additional evidence.

An open TCP port **5432 alone must not** select `postgres_cis`.

### Confidence and reconciliation

| Case | Behavior |
|------|----------|
| Declared == discovered | Effective fact confirmed; both provenances kept |
| Declared missing | Strong discovered fact becomes effective |
| Conflict | Record conflict; do not select dependent frameworks; add clarification |
| Low confidence | Supporting evidence only; cannot select frameworks alone |
| Port-only PostgreSQL | Weak evidence; framework rejected |

Declared inventory facts are **never overwritten**.

### Timeouts, retries, typed errors

Per-host settings (defaults shown):

* `connection_timeout` = 15s
* `command_timeout` = 30s
* `retry_count` = 1 (one retry after the initial attempt)

Typed issues: `connection_timeout`, `authentication_failed`,
`host_unreachable`, `command_timeout`, `unsupported_transport`,
`discovery_failed`, `partial_discovery`.

Failure on one host does not stop discovery for other hosts. Unavailable hosts
remain in the inventory/plan with structured issues, discovery limitations, and
unresolved operator questions. Frameworks that need unconfirmed facts are not
selected.

### Discovery evidence storage

```text
artifacts/<client_slug>/preflight/<inventory_version_id>/<host_id>/
  discovery.json
  commands.json
```

May contain command text, exit code, sanitized stdout/stderr, timestamp,
transport, host id. Must not contain passwords, tokens, private-key content /
passphrases, secret references, or credential-bearing connection strings.
Defense-in-depth secret scanning rejects evidence that still contains canaries.

### Deterministic preflight revisions

Each analyze persists a preflight revision with:

`inventory_version_id`, `inventory_content_hash`, `discovery_result_hash`,
`effective_facts_hash`, `selected_frameworks`, `collector_versions`,
`created_at`.

Repeated discovery with identical normalized results yields the same effective
result hash. Timestamps and volatile command output are excluded from the hash.
A meaningful change creates a new revision and invalidates the previous
unexecuted plan.

## Framework selection

| Signal | Framework |
|--------|-----------|
| Linux / Ubuntu | `ubuntu_cis_24_l2` |
| Windows Server | `windows_server` |
| Confirmed PostgreSQL | `postgres_cis` |
| General assessment | `host_facts` |

The plan records why each framework was selected, rejected, or left pending
clarification.

Example (Testcompany): 5 hosts, 4 Linux, 1 Windows, 2 confirmed PostgreSQL →
4 Linux audits + 1 Windows audit + 2 PostgreSQL audits + general host
assessment, plus any discovery limitations / conflicts / questions.

## Confirmation gate and stale plans

`audit start` without `--confirm` fails with `plan_not_confirmed`.

On `--confirm` / API approve:

1. Load the confirmed plan (no automatic discovery)
2. Verify inventory `version_id` + `content_hash`
3. Verify preflight / effective discovery hashes when present
4. Reject `plan_stale` when inventory or discovery facts diverged
5. Execute the confirmed plan scope (scope changes require a new confirmation)

## API

| Method | Path | Notes |
|--------|------|--------|
| POST | `/clients/{client_id}/inventory` | Validate |
| POST | `/clients/{client_id}/inventory/analyze` | Analyze + draft plan (`discovery` default true) |
| POST | `/clients/{client_id}/audit-plans` | Same as analyze |
| POST | `/audit-plans/{plan_id}/confirm` | Stale-checked; `start=true`; optional `refresh_discovery` |

## SSH / WinRM limitations

* SSH: read-only remote shell; no privilege escalation; host-key policy follows
  inventory / settings (`SSH_STRICT_HOST_KEY`).
* WinRM: read-only PowerShell; NTLM/basic per inventory; no configuration
  changes.
* Unit tests never connect to external infrastructure; WinRM is covered by a
  deterministic fake transport when a Windows runner is unavailable. At least
  one integration test uses a real SSH test server (in-process asyncssh).

## Module map

| Concern | Module |
|---------|--------|
| Domain inventory | `src/auditor/domain/inventory.py` |
| Domain audit plan | `src/auditor/domain/audit_plan.py` |
| Loaders / normalize / detect / select / plan | `src/auditor/inventory/` |
| Discovery + reconcile | `src/auditor/inventory/discovery.py` |
| SSH / WinRM / composite collectors | `src/auditor/inventory/collectors.py` |
| Evidence + secret scan | `src/auditor/inventory/discovery_evidence.py` |
| Preflight revisions | `src/auditor/inventory/preflight.py` |
| CLI | `src/auditor/cli.py` (`psql-auditor`) |
| HTTP | `src/auditor/api/inventory_routes.py` |
| Tests | `tests/test_inventory_driven_audit.py`, `tests/test_input005_discovery.py`, `tests/integration/test_ssh_discovery_container.py` |

## Open limitations (not accepted as done)

- `INPUT-005` remains `[~]` until independent acceptance review.
- Clarifications, exceptions, historical comparison, and report regeneration
  remain under later checklist items / `CORE-006` / `E2E-001`.
- `INPUT-001` and `CORE-006` stay open/partial until independent acceptance.
- Execution still requires a Markdown `INVENTORY.md` path for semantic
  AuditRequest validation even when YAML/JSON was used for planning.

# Open WebUI slash commands (Workspace prompts)

Reusable chat shortcuts installed into Open WebUI **Workspace → Prompts**.
Type `/` in the chat input to pick a command. Most expand into the same
phrase-based intents the auditor already understands.

## Install / refresh

```bash
python3 openwebui/install_owui_prompts.py
```

Requires Open WebUI up and `.env` credentials (`OPEN_WEBUI_EMAIL` /
`OPEN_WEBUI_PASSWORD`). Prompts are marked public-read so all users see them.

Source of truth for the catalog: [`openwebui/install_owui_prompts.py`](../openwebui/install_owui_prompts.py).

## Which model?

| Slash group | Model |
|-------------|--------|
| Sessions, audit, follow-up, ad-hoc, report | **auditor** |
| `/dashboard` | **Visualizer** (LiteLLM + Inline Visualizer tool) |

## Command catalog

### Sessions (results warehouse)

Requires `RESULTS_DB_ENABLED=true`. See also [`results-database.md`](results-database.md).

| Slash | Expands to | Notes |
|-------|------------|--------|
| `/list-sessions` | `List audit sessions` | Table of session `#`, client, status |
| `/sessions-continue` | `Which sessions need continue?` | Interrupted sessions only |
| `/list-sessions-client` | `Show me audit sessions for {{client}}` | Filter by client name |
| `/list-results` | `List results for {{client}} session {{n}}` | Warehouse REQ cells + host summary for that session |
| `/continue` | `continue` | Newest interrupted session |
| `/continue-session` | `continue session {{n}} for {{client}}` | Explicit session number |

**Finished (`completed`) sessions:** do not use `/continue*`. Use
`/list-results`, follow-up, or `/update-report` against that client’s
evidence instead.

Free-text equivalents for results:

```text
List results for AlphaCo session 2
list-results AlphaCo 2
Show warehouse results for AlphaCo #2
Результаты для AlphaCo сессия 2
```

### Audit start

| Slash | Expands to | Notes |
|-------|------------|--------|
| `/start-it-audit` | `Start an IT audit` | Begins IT checklist intake |

For CIS / other frameworks, type free text (or add more prompts) — see
[`starting-an-audit.md`](starting-an-audit.md).

### Post-audit follow-up

Evidence stays under `artifacts/<Client>/…`. See [`post-audit-followup.md`](post-audit-followup.md).

| Slash | Expands to | Notes |
|-------|------------|--------|
| `/gather-req` | `Gather evidence for {{req}} on {{framework}} for {{client}}. {{hint}}` | Tools only; appends logs (`003_…`). Default framework `it_audit` |
| `/refill-req` | `Prepare new observation and recommendation for {{req}} for {{client}}` | Rewrites cells from disk; no new SSH |
| `/revise-req` | `Revise {{req}} on {{framework}} for {{client}}` | Gather + refill in one turn |
| `/update-report` | `Update the report for {{client}}` | Rebuild `report.md` + ZIP |

Always fill **client** (and **req**) so the agent does not pick the wrong
artifacts folder.

### Ad-hoc (no full checklist)

See [`adhoc-commands.md`](adhoc-commands.md). Toggle with `ADHOC_COMMANDS_ENABLED`.

| Slash | Expands to | Notes |
|-------|------------|--------|
| `/run-command` | `Run this command: \`{{command}}\`` | SSH via inventory / secrets |
| `/run-sql` | `Execute SQL: {{sql}}` | Postgres MCP |

### Visualizer dashboard

| Slash | Expands to | Notes |
|-------|------------|--------|
| `/dashboard` | Interactive dashboard prompt for `{{client}}` (+ optional notes) | Switch model to **Visualizer** first |

Inline Visualizer setup: [`openwebui/inline-visualizer-v2/INSTALL.md`](../openwebui/inline-visualizer-v2/INSTALL.md).

## Variables

When a command has `{{…}}` fields, Open WebUI shows a form before send:

| Variable | Type | Used by |
|----------|------|---------|
| `client` | text (required) | sessions client, report, follow-up, dashboard, `/list-results` |
| `n` | number (required) | `/continue-session`, `/list-results` |
| `req` | text (required) | `/gather-req`, `/refill-req`, `/revise-req` (e.g. `REQ-001`) |
| `framework` | text (default `it_audit`) | gather / revise |
| `hint` | textarea | optional SSH/SQL hint on gather |
| `command` | text | `/run-command` |
| `sql` | textarea | `/run-sql` |
| `notes` | textarea | `/dashboard` |

## Related free-text phrases (no slash)

Slash commands only cover the common English shortcuts. Equivalent Russian /
extra phrases still work when typed fully — see
[`user-manual-ru.md`](user-manual-ru.md), [`results-database.md`](results-database.md),
and [`post-audit-followup.md`](post-audit-followup.md).

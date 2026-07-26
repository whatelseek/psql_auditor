# Open Terminal and Agent Framework Setup

This guide explains:

- how to configure Open WebUI + Open Terminal file browser for this project;
- how to add a new audit agent framework (`agents/*.md`).

## Configure Open Terminal File Browser

Open WebUI file browsing for terminal sessions is powered by a separate
Open Terminal backend. The folders shown in File Browser come from the
Open Terminal container filesystem, not from Open WebUI container mounts.

### 1) Environment variables

Set these in `.env`:

```env
OPEN_TERMINAL_HOST_PORT=9900
OPEN_TERMINAL_API_KEY=sk-open-terminal-local
OPEN_TERMINAL_SUPP_GID=1001

OWUI_AGENTS_PATH=./agents
OWUI_ARTIFACTS_PATH=./artifacts
OWUI_INVENTORY_PATH=./inventory
```

`OPEN_TERMINAL_SUPP_GID` is used to grant write access to bind-mounted
folders like `inventory` on Linux hosts with non-matching UID/GID.

### 2) Docker Compose services

Ensure `docker-compose.yml` has:

- `open-terminal` service on port `8000` (host-mapped to `9900`);
- folder mounts into `/home/user/workspace/*`;
- `group_add` with `${OPEN_TERMINAL_SUPP_GID}`;
- `open-webui` depending on `open-terminal`.

Example (project-specific essentials):

```yaml
open-webui:
  depends_on:
    - agent
    - open-terminal

open-terminal:
  image: ghcr.io/open-webui/open-terminal:main
  group_add:
    - "${OPEN_TERMINAL_SUPP_GID:-1001}"
  ports:
    - "${OPEN_TERMINAL_HOST_PORT:-9900}:8000"
  environment:
    OPEN_TERMINAL_API_KEY: ${OPEN_TERMINAL_API_KEY:-sk-open-terminal-local}
  volumes:
    - open-terminal-home:/home/user
    - ${OWUI_AGENTS_PATH:-./agents}:/home/user/workspace/agents:ro
    - ${OWUI_ARTIFACTS_PATH:-./artifacts}:/home/user/workspace/artifacts
    - ${OWUI_INVENTORY_PATH:-./inventory}:/home/user/workspace/inventory
```

### 3) Start/restart services

```bash
docker compose up -d open-terminal open-webui
```

### 4) Open WebUI connection settings

In Open WebUI:

- `Settings -> Integrations -> Open Terminal`
- URL: `http://open-terminal:8000`
- Auth type: `Bearer`
- API key: `OPEN_TERMINAL_API_KEY` value from `.env`

If your browser/UI setup prefers host loopback, `http://localhost:9900`
can also work, but `http://open-terminal:8000` is the Compose-native default.

### 5) Verify connectivity

From host:

```bash
curl http://localhost:9900/health
```

From Open WebUI container:

```bash
docker compose exec -T open-webui curl -s http://open-terminal:8000/health
```

Expected output:

```json
{"status":"ok"}
```

### 6) Verify file browser paths

Expected paths in Open Terminal:

- `/home/user/workspace/agents`
- `/home/user/workspace/artifacts`
- `/home/user/workspace/inventory`

If `inventory` is not writable, validate group mapping:

```bash
docker compose exec -T open-terminal sh -lc 'id'
```

The process should include group `1001` (or your configured
`OPEN_TERMINAL_SUPP_GID`).

## Troubleshooting "not accessible"

If Open WebUI reports the terminal as inaccessible:

1. Remove old terminal connections in Open WebUI and add a new one.
2. Re-check URL and key (`http://open-terminal:8000`, Bearer key).
3. Confirm health endpoint from both host and Open WebUI container.
4. Restart Open WebUI after config changes:
   `docker compose restart open-webui`
5. Hard refresh browser (`Ctrl+F5`) to clear stale UI state.

## Add a New Agent Framework

In this project, an "agent" is a Markdown framework file under `agents/`.
Drop in a new `.md` file — no Python changes are required. The Markdown
framework registry validates each file on load.

### 1) Create framework file

Create `agents/<framework_id>.md`. **YAML frontmatter is optional.**

Without frontmatter the registry derives:

- `id` from the filename stem;
- `title` from the first H1;
- `version` as a deterministic `src-<hash>` token from the file contents.

Optional frontmatter example:

```markdown
---
id: my_framework
version: "1.0"
aliases: [my framework, my_audit]
description: My custom audit framework
applicability: Linux servers running my_service
discovery_guidance: Confirm my_service is installed before selecting this framework
domain: it
detect:
  os_ids: [ubuntu, debian]
---
```

For bilingual routing, define language metadata:

```markdown
language: en   # en | ru
family_id: my_framework
```

`family_id` ties RU/EN variants together so router can choose the same
framework family in the operator's language.

### 2) Add requirements

Use stable requirement headings (`##` or `###`) with ids such as `REQ-*` or
`CTRL-*`. Metadata values may be single-line or multiline (including Markdown
lists):

```markdown
## REQ-001: Example control
**Category:** Access Control
**Severity:** High
**Applicability:** Ubuntu 24.04
**Evidence required:** Command output excerpt
**How to verify:**
1. Run specific command
2. Inspect the resulting file
**Pass criteria:** Explicit expected secure state.
**Fail criteria:** Explicit insecure state.
**Insufficient evidence criteria:** When evidence cannot be collected.
**Recommendation:** Remediation hint for operators.
```

`Verification guidance:` is accepted as an alias of `How to verify:`.

Guidelines:

- Keep `Pass criteria` explicit and human-readable.
- Keep one check intent per requirement.
- Prefer deterministic command-based verification text.
- Duplicate framework ids / requirement ids, or empty required fields, make the
  framework **invalid**: it still appears in the catalog with errors, but is
  not routed or executed.

### 3) LLM retrieval shape

Assessment prompts never receive an entire framework body. The runtime exposes:

1. compact framework catalog (ids, versions, applicability, validity);
2. compact requirement index for the selected framework;
3. full text for the **current** requirement only.

### 4) Deploy and test

After file changes:

```bash
docker compose up -d --build agent
```

Then in Open WebUI request an audit mentioning framework id/alias.

### 5) Optional host-based auto-selection

Use `detect` frontmatter (`always`, `os_ids`, `binaries`, `ports`) so
frameworks can be selected from discovered host facts.

## RU/EN framework routing

The router automatically detects request language (`ru`/`en`) and prefers a
matching framework variant when available.

Example pair:

- `agents/postgres_cis.md` (`language: en`, `family_id: postgres_cis`)
- `agents/postgres_cis_ru.md` (`language: ru`, `family_id: postgres_cis`)

If no matching language variant exists for a family, routing falls back to the
available framework file.


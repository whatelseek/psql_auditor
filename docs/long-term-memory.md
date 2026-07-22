# Long-term memory (procedural playbooks)

**auditor** uses [LangGraph / LangChain long-term memory concepts](https://docs.langchain.com/oss/python/concepts/memory) as **procedural memory**: remembered *how* to verify requirements for each framework (PostgreSQL, Ubuntu, …).

This is **not** chat history. Short-term (thread) memory remains the HITL checkpointer; long-term memory is a **playbook store**.

## What is stored

| Kind | Content |
|------|---------|
| **Procedural** | Preferred tool calls (`ssh_run`, `mcp_query`, …) per `REQ-*` |
| Framework tips | Short rules for the whole framework (from seed YAML) |

Runtime shape (in-process cache):

```text
namespace = ("playbooks", "<framework_id>")
key       = "REQ-001" | "_framework"
value     = { tools: [...], notes, source: seed|learned, updated_at }
```

## Seed playbooks

Editable YAML under [`agents/playbooks/`](../agents/playbooks/) (git-managed):

- `postgres_cis.yaml`
- `ubuntu_cis_24_l2.yaml`
- `it_audit.yaml`

Example:

```yaml
framework_id: ubuntu_cis_24_l2
framework_tips:
  - Prefer ssh_read_file for config files; ssh_run for status commands.
requirements:
  REQ-002:
    notes: Check PermitRootLogin
    tools:
      - name: ssh_run
        arguments:
          command: "grep -Ei '^\\s*PermitRootLogin' /etc/ssh/sshd_config"
```

Add a new framework playbook whenever you add `agents/<name>.md`.

## Learning (hot path)

When `MEMORY_LEARN=true`, a **successful** tool call (no SSH/MCP error) is
upserted into the RAM cache and flushed to:

| Backend | Where | When |
|---------|--------|------|
| **Postgres (preferred)** | Shared results DB table `playbook_memory` | `RESULTS_DB_ENABLED=true` |
| **JSON fallback** | `memory/learned_playbooks.json` | Warehouse off or PG unreachable |

Reads stay in **RAM** (`InMemoryStore`) after startup — Postgres is for durability
and multi-replica sharing, not hot-path latency.

Learned recipes overlay seeds on the next process start. Failures are never stored.
If JSON exists and Postgres is empty, entries are **migrated once** into
`playbook_memory`.

Seeds are **not** written to Postgres (stay in YAML).

## How it speeds audits

The evidence prompt includes a **playbook memory** block. The model is instructed
to run preferred commands first → fewer exploratory ReAct rounds → faster audits
and more consistent checks.

## Config

| Env | Default | Meaning |
|-----|---------|---------|
| `PLAYBOOKS_DIR` | `agents/playbooks` | Seed YAML |
| `MEMORY_DIR` | `memory` | JSON fallback directory |
| `MEMORY_ENABLED` | `true` | Inject playbooks into prompts |
| `MEMORY_LEARN` | `true` | Remember successful tools |
| `RESULTS_DB_ENABLED` | (compose: `true`) | Persist learned recipes to Postgres |
| `RESULTS_DATABASE_URL` | results-db DSN | Shared warehouse (not per-client DB) |

Playbook rows live on the **shared** warehouse database named in
`RESULTS_DATABASE_URL` (table `playbook_memory`), not in `results_<client>` DBs.

## Related

- Results warehouse: [`results-database.md`](results-database.md)
- LangChain memory overview: https://docs.langchain.com/oss/python/concepts/memory
- Starting audits: [`starting-an-audit.md`](starting-an-audit.md)
- Ad-hoc playbook path: [`adhoc-commands.md`](adhoc-commands.md)

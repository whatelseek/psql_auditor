# Long-term memory (procedural playbooks)

**auditor** uses [LangGraph / LangChain long-term memory concepts](https://docs.langchain.com/oss/python/concepts/memory) as **procedural memory**: remembered *how* to verify requirements for each framework (PostgreSQL, Ubuntu, Windows, …).

This is **not** chat history. Short-term (thread) memory remains the HITL checkpointer; long-term memory is a **playbook store**.

## What is stored

| Kind | Content |
|------|---------|
| **Procedural** | Preferred tool calls (`ssh_run`, `mcp_query`, …) per `REQ-*` |
| Framework tips | Short rules for the whole framework |

LangGraph store shape:

```text
namespace = ("playbooks", "<framework_id>")
key       = "REQ-001" | "_framework"
value     = { tools: [...], notes, source: seed|learned, updated_at }
```

## Seed playbooks

Editable YAML under [`agents/playbooks/`](../agents/playbooks/):

- `postgres_cis.yaml`
- `ubuntu_cis.yaml`
- `windows_cis.yaml`

Example:

```yaml
framework_id: ubuntu_cis
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

When `MEMORY_LEARN=true`, a **successful** tool call (no SSH/MCP error) is upserted into memory for that REQ and flushed to:

```text
memory/learned_playbooks.json
```

Learned recipes overlay seeds on the next process start. Failures are never stored.

## How it speeds audits

The evidence prompt includes a **playbook memory** block. The model is instructed to run preferred commands first → fewer exploratory ReAct rounds → faster audits and more consistent checks.

## Config

| Env | Default | Meaning |
|-----|---------|---------|
| `PLAYBOOKS_DIR` | `agents/playbooks` | Seed YAML |
| `MEMORY_DIR` | `memory` | Learned overlay |
| `MEMORY_ENABLED` | `true` | Inject playbooks into prompts |
| `MEMORY_LEARN` | `true` | Remember successful tools |

Docker mounts `./memory` so learning survives container restarts.

## Related

- LangChain memory overview: https://docs.langchain.com/oss/python/concepts/memory
- Starting audits: [`starting-an-audit.md`](starting-an-audit.md)

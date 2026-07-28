---
name: frameworks
description: Versioned Framework Registry over Markdown checklists in the agents directory.
triggers:
  - "framework"
  - "agents"
  - "checklist"
  - "FrameworkRegistry"
  - "requirement"
edges:
  - target: context/capability-model.md
    condition: when selecting frameworks from host capabilities
  - target: context/workflow.md
    condition: when loading frameworks in the graph
  - target: context/decisions.md
    condition: ADR: Versioned Framework Registry
grounds_to:
  - node: "class:807cb593a848237fd63c2263f1d5a555"
    fingerprint: "mh:64:79adb3ab1e3539906e69433e29f889b313dd8b95f9e88cd37c01278535f284e7"
last_updated: 2026-07-28
---

# Framework Registry

## Source of truth

Administrator-authored Markdown under `agents/` (optional YAML frontmatter: `id`, `aliases`, `description`). Bundled examples: `postgres_cis`, `ubuntu_cis_24_l2`, `host_facts`, `windows_server` (+ `_ru` variants).

No Python change is required to add a framework file; `FrameworkRegistry.load` discovers and validates.

## Registry API

Module: `src/auditor/framework_registry.py` — [`FrameworkRegistry`](mex://class:807cb593a848237fd63c2263f1d5a555).

- Validates structure; non-executable frameworks remain visible in catalog but `require_executable` fails closed
- Deterministic `framework_version` from source hash
- Compact catalog / requirement index text for LLM routing prompts
- `get_requirement_prompt_block` / `load_framework_checklist` refuse unvalidated ad-hoc parse paths

Status: **INPUT-002 / AGENT-001 partial** — registry exists; independent acceptance still open for full strictness.

## Applicability

`inventory/select_frameworks.py` maps `HostCapabilitySnapshot` + inventory declarations to decisions: `selected`, `not_applicable`, `requires_operator_decision`, `unsupported`, `blocked`. Plans record those decisions with framework hashes.

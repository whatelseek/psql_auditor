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

Markdown frameworks may expose **strict structured applicability metadata** in front matter (`applicability`, `required_capabilities`, `required_facts`, `discovery_hints`), parsed by `auditor.domain.applicability.parse_applicability_meta` and `auditor.inventory.framework_meta`.

- Invalid structured metadata remains **catalog-visible** but **non-executable**; sanitized validation errors are attached.
- Legacy frameworks without structured metadata keep their previous executable state.
- Predicates consume **normalized fact values only** (INPUT005-10); they do not run eval/regex/Jinja.
- Production framework **selection** defaults to declarative Markdown applicability (`select_frameworks_dynamic`). The hardcoded tech map remains opt-in via `use_legacy_tech_mapping=True`. Plans still record `selected` / `not_applicable` / `requires_operator_decision` / `unsupported` / `blocked`.


## Declarative selection (INPUT005-12 / INPUT005-13)

- Candidate evaluation covers every host/framework pair (`evaluate_framework_candidates`).
- Predicates consume normalized fact maps only (`HostFactSet.as_value_map()`).
- Target scope (`client` / `host` / `service`) is declared in Markdown `target:` metadata.
- Capability readiness is host-specific via authorized tools and inventory access facts.
- Applicability match and authorization readiness are separate decisions.
- Default production selector is declarative (`select_frameworks_dynamic`); the hardcoded
  `_TECH_FRAMEWORK_PREFERENCES` path is compatibility-only via `use_legacy_tech_mapping=True`.
- Candidate evaluation never binds or invokes tools.
- Full evidence-backed selection provenance is deferred to INPUT005-18.

## Capability discovery planning (INPUT005-14)

- Discovery proposals use **typed `discovery_hints` only** — never framework IDs, titles, ports, or Markdown prose.
- Planning (`build_capability_discovery_plan`) is separate from execution (INPUT005-15+).
- Invalid inventory hosts are blocked before hint/operation evaluation.
- Hint alternatives for the same missing fact are evaluated together; blocked hints cannot hide a planned alternative.
- `required_capabilities.all_of` resolves independently; `any_of` is one alternative group (`capability_options`).
- Framework metadata resolves only by exact `(framework_id, framework_version)` — no id-only fallback.
- `AuditPlan` pins `discovery_plan_hash` and secret-free `framework_catalog_hash`; confirmation rejects stale discovery plans / catalogs.


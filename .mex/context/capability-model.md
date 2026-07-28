---
name: capability-model
description: HostCapabilitySnapshot, technology detection, and capability-based tool/framework selection.
triggers:
  - "capability"
  - "HostCapabilitySnapshot"
  - "discovery"
  - "technology"
  - "select frameworks"
edges:
  - target: context/tool-security.md
    condition: when resolving which tools may run
  - target: context/frameworks.md
    condition: when mapping capabilities to frameworks
  - target: patterns/capability-resolution.md
    condition: implementation pattern
grounds_to: []
last_updated: 2026-07-28
---

# Capability model

## HostCapabilitySnapshot

`domain/host_capability.py` — v1 snapshot of OS info, access methods, and technologies discovered or declared for a host. Serialized into plan/discovery artifacts (secret-free).

Technology statuses used in detection (`inventory/detect.py`): `confirmed`, `suspected`, `absent`, `unknown`, `unsupported`.

## Capability-based tool selection

Discovery does not hard-code ad-hoc SSH strings in the happy path. `inventory/tool_discovery.py` selects tools via Tool Registry (`select_discovery_tools`, `RegistrySshTransport`). Capability policy profiles (e.g. POC under `tools/policies/`) gate which catalog entries are bindable.

## Framework selection

`select_frameworks_for_inventory` defaults to declarative Markdown applicability
(`select_frameworks_dynamic` / INPUT005-13). Candidates are evaluated for every
host/framework pair (INPUT005-12) against normalized facts. Capability readiness
is host-specific (authorized tools whose `inventory_access` segments are available
on that host) and does not change applicability match/not-match results.

The hardcoded `_TECH_FRAMEWORK_PREFERENCES` selector remains available only via
`use_legacy_tech_mapping=True` (compatibility). Applicability and authorization
are separate decisions. Full selection provenance is deferred to INPUT005-18.

## Normalized facts

`auditor.domain.normalized_facts` builds a stable per-host fact namespace (`asset.*`, `os.*`, `access.*`, `service.*`, `port.*`, `technology.*`) with `source_type`, `source_ref`, confidence, and evidence refs. Conflicts for the same key with different values are recorded explicitly and **not** silently resolved (no last-write-wins). Conflicted keys are omitted from `HostFactSet.as_value_map()`.

Applicability predicates evaluate against that value map only.

## Boundary

Capabilities describe **what the host can be assessed with**, not authorization to run arbitrary commands. Authorization is Tool Registry + policy + SSH allow-lists. Candidate evaluation must not invoke tools.

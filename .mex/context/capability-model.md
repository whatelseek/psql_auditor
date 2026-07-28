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

`select_frameworks_for_inventory` still consumes technology detections + inventory via the existing production mapping. Structured applicability metadata and normalized facts are foundations for later declarative selection (INPUT005-12/13) and are **not** the production selector yet.

## Normalized facts

`auditor.domain.normalized_facts` builds a stable per-host fact namespace (`asset.*`, `os.*`, `access.*`, `service.*`, `port.*`, `technology.*`) with `source_type`, `source_ref`, confidence, and evidence refs. Conflicts for the same key with different values are recorded explicitly and **not** silently resolved (no last-write-wins). Conflicted keys are omitted from `HostFactSet.as_value_map()`.

Applicability predicates evaluate against that value map only.

## Boundary

Capabilities describe **what the host can be assessed with**, not authorization to run arbitrary commands. Authorization is Tool Registry + policy + SSH allow-lists. Candidate evaluation must not invoke tools.

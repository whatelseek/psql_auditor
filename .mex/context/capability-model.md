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

`select_frameworks_for_inventory` consumes snapshots + client inventory. Unsupported classes (e.g. certain Cisco network devices in current code) are marked unsupported rather than silently audited.

## Boundary

Capabilities describe **what the host can be assessed with**, not authorization to run arbitrary commands. Authorization is Tool Registry + policy + SSH allow-lists.

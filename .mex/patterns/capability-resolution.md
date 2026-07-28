---
name: capability-resolution
description: Resolve bindable tools and frameworks from registry + host capabilities.
triggers:
  - "capability policy"
  - "bindable tools"
  - "select_discovery_tools"
edges:
  - target: context/capability-model.md
    condition: model
  - target: context/tool-security.md
    condition: registry
grounds_to: []
last_updated: 2026-07-28
---

# Capability resolution

## Context
`ToolRegistry` + `load_capability_policy` + `HostCapabilitySnapshot` drive what may run.

## Steps
1. Load registry/policy; refuse bind if `executable` false or unauthorized.
2. For discovery, call `select_discovery_tools` / registry transports — do not bypass with raw Paramiko in new code.
3. Pin `tool_catalog_hash` / `capability_policy_hash` on plan and assert with `assert_tool_snapshot_current` at start.
4. Map snapshot technologies to frameworks via `select_frameworks_for_inventory`.

## Gotchas
- Catalog visibility ≠ authorization to bind.
- Stale hashes must fail closed (`tool_snapshot_stale`).

## Verify
- [ ] Unauthorized tool not in `bindable_langchain_tools`
- [ ] Plan start rejects rotated catalog without re-plan

## Debug
Dump `registry.catalog()` and policy profile name (POC).


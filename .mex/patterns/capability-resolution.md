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
4. Map normalized facts to frameworks via declarative `select_frameworks_for_inventory`
   (default dynamic path). Do not infer applicability from framework IDs or titles.
5. Treat capability readiness as host-specific and separate from predicate match results.
6. Candidate evaluation never invokes tools; authorization uses `registry.authorized_tools()` only.


7. Build typed capability discovery plans from missing facts/capabilities + `discovery_hints` + authorized manifests; check host `access.<segment>.available` generically; dedupe identical host/operation work across frameworks (never across hosts).
8. Prefer planned hint alternatives over blocked/operator ones; keep `any_of` as one group; require exact framework metadata identity.
9. Use one ToolRegistry snapshot for candidate evaluation, discovery planning, and AuditPlan tool hashes.
10. Pin `discovery_plan_hash` + `framework_catalog_hash` on `AuditPlan` / plan revision; assert on confirm/start with the same logical catalog.

## Gotchas
- Catalog visibility ≠ authorization to bind.
- Hardcoded tech→framework mapping is opt-in only (`use_legacy_tech_mapping`).
- Capability unavailability must not rewrite `not_applicable` into `blocked`.
- Stale hashes must fail closed (`tool_snapshot_stale`).

## Verify
- [ ] Unauthorized tool not in `bindable_langchain_tools`
- [ ] Plan start rejects rotated catalog without re-plan

## Debug
Dump `registry.catalog()` and policy profile name (POC).


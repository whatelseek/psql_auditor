---
name: tool-security
description: Tool Registry, capability policy, SSH allow-lists, MCP registry, and secret handling.
triggers:
  - "tool registry"
  - "SSH"
  - "MCP"
  - "capability policy"
  - "secrets"
  - "allow-list"
edges:
  - target: context/capability-model.md
    condition: for host-driven selection
  - target: context/evidence-model.md
    condition: for ToolResult provenance
  - target: patterns/tool-provenance.md
    condition: when writing evidence sidecars
  - target: patterns/capability-resolution.md
    condition: when binding tools for LLM/runtime
grounds_to:
  - node: "class:a76e423f08f4386bde84cb33bfff24ca"
    fingerprint: "mh:64:3fe5e65f2900b03062414364e5734d3754c668f6e5b9990ca983b2d8d69c1c5c"
last_updated: 2026-07-28
---

# Tool security

## Tool Registry

[`ToolRegistry`](mex://class:a76e423f08f4386bde84cb33bfff24ca) in `src/auditor/tool_registry.py` + `tools/catalog/*.json`.

- Catalog root is `settings.tools_dir` (`TOOLS_DIR`; default `tools`, container `/app/tools`)
- `ApplicationRuntime.start()` always validates the registry (including constructor-injected ones) against `settings.tools_dir` + `expected_profile` before graph construction; origin path mismatches and fake registries fail closed. Injected registries are compared against a fresh on-disk `load_tool_registry(TOOLS_DIR)` snapshot (hashes, policy, complete required ToolManifest fields (including issues/schemas/limits)); mismatches raise `registry_snapshot_mismatch`. Startup errors expose only code/tool ID/profile/catalog path — never raw manifest/policy values.
- Manifests declare transport, entrypoint, limits, executability
- Invalid tools may appear in catalog but are **not** LLM-bound
- Plan/run pin `tool_catalog_hash` and `capability_policy_hash`; stale snapshots raise `tool_snapshot_stale`
- SSH adapters: `ssh_run`, `ssh_read_file` (`TOOL-001` partial; packaging/startup validation = TOOL001-07)

## Capability policy

`tools/policies/` (POC profile). `CapabilityPolicy` + `is_authorized` / `require_authorized`. Graph binds tools via `_registry_ssh_tools` / `bindable_langchain_tools`.

## SSH policy

Command allow-list lives in `tools/policies/<profile>.json`:

- `ssh_allowed_commands` — exact command strings
- `ssh_allowed_command_patterns` — regexes (`fullmatch`)
- `ssh_allow_all_commands` — PoC/lab only: approve any non-empty command (skips allow-list **and** shell-composition gates). Default `false`. PoC profile sets `true`.

`tools/ssh_policy.py` enforces those (falls back to builtins only when both allow-list keys are omitted), plus approved read paths, no shell composition (unless allow-all), timeouts, and stdout/stderr redaction (`tools/secrets.py`). Empty lists deny-all when allow-all is off. Restart the agent after editing policy (registry is loaded at startup). Non-zero exit → error ToolResult. Path allow-lists for `ssh_read_file` are unchanged by the PoC flag.

## WinRM / other transports

WinRM collectors/tools exist (`TOOL-002` partial) without full parity on policy/TLS/tests. HTTP/SNMP adapters largely absent (`TOOL-003`/`TOOL-005`). TCP probes exist in `access_probe.py` but are not first-class catalog tools (`TOOL-004`).

## MCP Registry

`mcp_registry.py` + `mcps/registry.json`: stdio/HTTP server specs, env resolution from settings, credential readiness checks. Credentials come from environment/settings — never from MEX or committed inventory plaintext in artifacts.

## Secrets

Resolve plaintext only inside runtime target scope for live calls. Persist `secret_ref` / `has_secret` only. Inventory credential tables may contain plaintext for operator convenience at rest under `inventory/` (gitignored patterns apply for keys); auditor domain objects strip them on load/normalize.

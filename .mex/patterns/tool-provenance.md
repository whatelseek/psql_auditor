---
name: tool-provenance
description: Attach ToolProvenance and catalog hashes to every evidence write.
triggers:
  - "provenance"
  - "ToolProvenance"
  - "command_hash"
edges:
  - target: context/evidence-model.md
    condition: schema
  - target: context/tool-security.md
    condition: policy
grounds_to: []
last_updated: 2026-07-28
---

# Tool provenance

## Context
`ToolResult.to_evidence_record` / `EvidenceStore.write_tool_result` must carry who/what/why hashes.

## Steps
1. Populate client, run, framework, requirement, asset ids on the result.
2. Include tool id, catalog hash, policy hash, and command/path hash for SSH.
3. Redact secrets from stdout/stderr before persist.
4. Prefer normalized `tool_result.v1` over ad-hoc text files for new adapters.

## Gotchas
- Missing provenance breaks later assessment defensibility.
- Non-SSH paths may still be transitional — extend, do not invent a third schema.

## Verify
- [ ] Sidecar JSON includes hashes
- [ ] Secrets not present in stored output

## Debug
Inspect evidence folder for the `audit_run_id` and requirement id.


---
name: agents
description: Always-loaded project anchor. Read this first. Contains project identity, non-negotiables, commands, and pointer to ROUTER.md for full context.
last_updated: 2026-07-28
---

# Infrastructure Auditor (psql_auditor)

## What This Is
A LangGraph-orchestrated infrastructure security auditor that turns client inventory into capability-selected tool runs, evidence, assessments, and reports — with human approval gates and versioned registries.

## Non-Negotiables
- Never store credentials, plaintext secrets, customer audit evidence, or reports in `.mex/` — MEX is architectural memory only
- LLM never executes tools directly; tools bind only through Tool Registry + capability policy
- Confirmed `AuditPlan` / `plan_revision_id` are immutable; confirm/start must pin exact revision
- Evidence collection is separate from assessment; do not mutate immutable framework fields in reports
- Secrets appear only as `secret_ref` / `has_secret` in inventory, plans, requests, logs, and persisted artifacts

## Commands
- Python gates: `make check` (or `make lint` / `make typecheck` / `make test`)
- Inventory: `psql-auditor inventory validate|analyze <Client>` then `audit plan|start`
- MEX: `npm run mex:graph` · `npm run mex:check` · `npm run mex:sync`
- Dev API: see `docs/starting-an-audit.md` and `Makefile`

## Code Graph
The repo is indexed into `.mex/graph.db`. Prefer `mex graph scope "<task>"` over grepping. Expand with `mex graph get <id> --detail source`. Before editing a symbol, run `mex impact <symbol|file>`.

## Scaffold Growth
After meaningful work: Ground → Record (ROUTER / context) → Orient (patterns) → Write (`last_updated`, `mex log` when rationale matters).

## Navigation
Start every session with `ROUTER.md`.

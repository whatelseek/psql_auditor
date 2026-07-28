---
name: setup-guide
description: How this MEX scaffold was populated for Infrastructure Auditor. Not the Python env setup — see context/setup.md.
last_updated: 2026-07-28
---

# Setup — Infrastructure Auditor MEX scaffold

This scaffold is **populated** for `psql_auditor`. Do not re-run empty-template prompts.

## Already done

- Local pinned `mex-agent@0.7.0` via `package.json` / `npm ci`
- Context wiki under `context/` (architecture through current-state)
- Subsystem routing in `ROUTER.md`
- Patterns under `patterns/`
- ADR decisions in `context/decisions.md`
- CI: `.github/workflows/mex.yml`

## Refresh after code changes

```bash
npm run mex:graph
npm run mex:check
```

Dev environment setup: [`context/setup.md`](context/setup.md).
Project state: [`context/current-state.md`](context/current-state.md).

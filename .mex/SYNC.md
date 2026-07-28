---
name: sync-guide
description: How to realign MEX scaffold with codebase changes for this auditor repo.
last_updated: 2026-07-28
---

# Sync

When architecture or checklist acceptance changes:

1. Update the relevant `context/*.md` surgically (especially `current-state.md`)
2. Update `ROUTER.md` Current Project State summary
3. Add/adjust patterns if a new recurring task appeared
4. `npm run mex:graph && npm run mex:check`
5. If check reports fixable drift: `npm run mex:sync` or `npx mex check --fix`

MEX must remain free of audit evidence, credentials, and customer reports.

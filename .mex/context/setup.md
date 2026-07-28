---
name: setup
description: Dev environment setup, quality gates, and MEX commands.
triggers:
  - "setup"
  - "install"
  - "make check"
  - "mex"
  - "venv"
edges:
  - target: context/stack.md
    condition: for versions
  - target: context/conventions.md
    condition: for verify checklist
grounds_to: []
last_updated: 2026-07-28
---

# Setup

## Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'   # or follow docs/baseline.md / Makefile
make check
```

Integration tests may need:

`AUDITOR_TEST_DATABASE_URL=postgresql://…@127.0.0.1:55432/postgres`

## MEX (architectural memory)

```bash
npm install                 # installs pinned mex-agent
npm run mex:graph           # build .mex/graph.db (gitignored)
npm run mex:check           # scaffold drift / link health
npm run mex:sync            # repair when check --fix
```

Do not `npm i -g mex-agent` for this project — use the local pin.

## Inventory smoke

Place `inventory/Testcompany/` fixtures, then validate/analyze/plan as in `docs/inventory-driven-audit.md`.

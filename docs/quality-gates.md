# AUD-002 — Unified local and CI quality gates

Local developers, Cursor, and GitHub Actions use the **same** Make targets.
A mandatory failure must produce a non-zero exit code locally and a red CI job.

## Canonical commands

| Command | Mutates tree? | Behavior |
|---------|---------------|----------|
| `make format` | yes | Apply `ruff format` to `src` and `tests` |
| `make format-check` | no | Fail when formatting would change files |
| `make lint` | no | `ruff check src tests` |
| `make typecheck` | no | `mypy src/auditor` |
| `make test-unit` | no | `pytest -m unit` via `scripts/run_pytest_group.py` |
| `make test-integration` | no | `pytest -m integration` via the same guard |
| `make test` | no | Full suite via the same guard |
| `make check` | no | `format-check` + `lint` + `typecheck` + unit + integration + full |

Empty discovery is an error for unit, integration, and the full suite.
`scripts/run_pytest_group.py` counts collected tests before running and exits
non-zero when the selection is empty (pytest exit code 5 cannot mask this).

## Markers

Registered in `pyproject.toml` with `--strict-markers`:

* `unit` — default for tests outside `tests/integration/`
* `integration` — PostgreSQL / live-service tests under `tests/integration/`
* `external_llm` — optional real-provider tests (not mandatory CI)

## PostgreSQL integration

Set `AUDITOR_TEST_DATABASE_URL` to an **admin** DSN that can `CREATE DATABASE`.
Each test creates `aud002_<hex>`, applies warehouse schema via `ResultsStore`,
and drops the database on teardown. Never point this at production data.

## Deterministic LLM

Mandatory tests install / use `auditor.testing.DeterministicFakeChatModel` through
`use_chat_model_factory`. An autouse network guard rejects accidental HTTP calls
to LLM endpoints unless `AUDITOR_ALLOW_EXTERNAL_LLM=1`.

## CI mapping

| CI job | Local command |
|--------|---------------|
| `format-check` | `make format-check` |
| `lint` | `make lint` |
| `typecheck` | `make typecheck` |
| `unit` | `make test-unit` |
| `integration` | `make test-integration` (+ Postgres service) |
| `full-suite` | `make test` (+ Postgres service) |
| `core-regression` | focused CORE-001/002/003 pytest files |

`continue-on-error` is not used on mandatory gates.
`make baseline-compare` remains optional historical tooling and is not a
substitute for green mandatory gates.

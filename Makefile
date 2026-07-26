# Canonical verification commands (AUD-002).
# Local developers, Cursor, and GitHub Actions must use these same targets.

PYTHON ?= python
PIP ?= $(PYTHON) -m pip
PYTEST_GROUP ?= $(PYTHON) scripts/run_pytest_group.py
RUFF ?= $(PYTHON) -m ruff
MYPY ?= $(PYTHON) -m mypy

.PHONY: help install install-locked lock format format-check lint typecheck \
	test-unit test-integration test validate-defect-map check baseline-compare

help:
	@echo "Targets:"
	@echo "  install-locked   Clean-checkout install using constraints.txt"
	@echo "  lock             Regenerate constraints.txt (pip-compile)"
	@echo "  format           Apply ruff formatter (may modify files)"
	@echo "  format-check     Ruff format --check (non-destructive)"
	@echo "  lint             Ruff check"
	@echo "  typecheck        mypy on src/auditor"
	@echo "  test-unit        Unit tests (-m unit); fails if zero collected"
	@echo "  test-integration Integration tests (-m integration); fails if zero collected"
	@echo "  test             Full pytest suite; fails if zero collected"
	@echo "  validate-defect-map  AUD-001 checklist↔defect-map completeness"
	@echo "  check            format-check + lint + typecheck + validate-defect-map + tests"
	@echo "  baseline-compare Optional: full suite vs docs/baseline-failures.txt"

install:
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev]'

install-locked:
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev]' -c constraints.txt

lock:
	$(PIP) install 'pip-tools>=7.4.0'
	$(PYTHON) -m piptools compile \
		--extra=dev \
		--resolver=backtracking \
		--strip-extras \
		-o constraints.txt \
		pyproject.toml

format:
	$(RUFF) format src tests

format-check:
	$(RUFF) format --check src tests

lint:
	$(RUFF) check src tests

typecheck:
	# Path form avoids shell wrappers that reject ``python -m mypy -p``.
	$(MYPY) src/auditor

test-unit:
	$(PYTEST_GROUP) -- -m unit -q

test-integration:
	$(PYTEST_GROUP) -- -m integration -q

test:
	$(PYTEST_GROUP) -- -q

validate-defect-map:
	$(PYTHON) scripts/validate_defect_map.py

# Mandatory non-destructive gates (identical locally and in CI).
check: format-check lint typecheck validate-defect-map test-unit test-integration test

baseline-compare:
	$(PYTHON) scripts/baseline_compare.py

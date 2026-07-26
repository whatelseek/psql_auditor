# Canonical verification commands (CORE-000).
# Prefer these over ad-hoc pytest invocations in CI and local review.

PYTHON ?= python
PIP ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
RUFF ?= $(PYTHON) -m ruff
MYPY ?= $(PYTHON) -m mypy

.PHONY: help install install-locked lock format-check lint typecheck \
	test-unit test-integration test check baseline-compare

help:
	@echo "Targets:"
	@echo "  install-locked   Clean-checkout install using constraints.txt"
	@echo "  lock             Regenerate constraints.txt (pip-compile)"
	@echo "  test-unit        Unit tests (-m unit)"
	@echo "  test-integration Integration tests (-m integration)"
	@echo "  test             Full pytest suite"
	@echo "  format-check     Ruff format --check"
	@echo "  lint             Ruff check"
	@echo "  typecheck        mypy on src/auditor"
	@echo "  check            format-check + lint + typecheck + test"
	@echo "  baseline-compare Full suite vs docs/baseline-failures.txt"

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

format-check:
	$(RUFF) format --check src tests

lint:
	$(RUFF) check src tests

typecheck:
	$(MYPY) -p auditor

test-unit:
	$(PYTEST) -m unit -q

test-integration:
	@# Exit code 5 = no tests collected (expected until live-service tests exist).
	@$(PYTEST) -m integration -q; \
	code=$$?; \
	if [ $$code -eq 5 ]; then \
		echo "No integration tests collected (documented in docs/baseline.md)."; \
		exit 0; \
	fi; \
	exit $$code

test:
	$(PYTEST) -q

# Mandatory non-destructive gates. Quality tools may be red at baseline;
# use ``make baseline-compare`` in CI to fail only on new test regressions.
check: format-check lint typecheck test

baseline-compare:
	$(PYTHON) scripts/baseline_compare.py

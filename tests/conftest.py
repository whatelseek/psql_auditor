"""Pytest defaults for CORE-000 unit/integration markers.

All tests under ``tests/`` are treated as ``unit`` unless explicitly marked
``integration``. There is currently no suite that requires live Docker /
PostgreSQL / SSH — warehouse and MCP tests use mocks — so ``make
test-integration`` is expected to collect zero tests until such cases are
added and marked.
"""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-apply ``unit`` when neither unit nor integration is set."""
    for item in items:
        markers = {m.name for m in item.iter_markers()}
        if "integration" in markers or "unit" in markers:
            continue
        item.add_marker(pytest.mark.unit)

"""Shared deterministic test fixtures (AUD-003).

Prefer :func:`tests.fixtures.canonical_audit.build_canonical_scenario` for new
workflow, history, reporting, anonymization, exception, and persistence tests.
Extend the canonical scenario in place rather than inventing parallel datasets.
"""

from tests.fixtures.canonical_audit import (
    FIXED_NOW,
    CanonicalScenario,
    build_canonical_scenario,
    exception_is_applicable,
)

__all__ = [
    "FIXED_NOW",
    "CanonicalScenario",
    "build_canonical_scenario",
    "exception_is_applicable",
]

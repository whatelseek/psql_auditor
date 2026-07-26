"""Temporary module for AUD-002 Check 2 controlled quality failures."""

import os  # unused — deliberate F401


def deliberate_type_error(value: int) -> int:
    return value + "not-an-int"  # deliberate mypy error

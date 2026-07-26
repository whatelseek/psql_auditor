"""Strict client name validation for inventory-driven workflows."""

from __future__ import annotations

import re

_CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


class InvalidClientNameError(ValueError):
    """Client name rejects spaces and non-latin/special characters."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(
            f"client name must contain only Latin letters, digits, and underscores (got {name!r})"
        )


def validate_client_name(name: str) -> str:
    """Validate and return a strict client directory / namespace name.

    Allowed: ``A-Z``, ``a-z``, ``0-9``, ``_``. Spaces and other special
    characters are rejected.

    Args:
        name: Raw client name from the operator.

    Returns:
        Stripped client name (casing preserved for directory naming).

    Raises:
        InvalidClientNameError: When the name is empty or invalid.
    """
    text = (name or "").strip()
    if not text or not _CLIENT_NAME_RE.fullmatch(text):
        raise InvalidClientNameError(name)
    return text

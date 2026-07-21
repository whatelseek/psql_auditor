"""Redact secrets before writing tool args to evidence or playbook memory.

Pipeline role:
    Called by ``PlaybookMemory.remember_tool`` and evidence writers so SSH
    passwords, API tokens, and similar fields never land in JSON artifacts
    or long-term procedural memory.
"""

from __future__ import annotations

from typing import Any

_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
        "ssh_password",
        "pg_password",
    }
)


def redact_secrets(value: Any) -> Any:
    """Return a deep copy of ``value`` with secret-looking fields masked.

    Recursively walks dicts and lists. Keys whose lowercase name appears in
    ``_SECRET_KEYS`` (e.g. ``password``, ``token``, ``api_key``) are replaced
    with ``***REDACTED***``. Non-container values are returned unchanged.

    Args:
        value: Arbitrary JSON-like structure (dict, list, or scalar).

    Returns:
        A new structure of the same shape with sensitive dict values redacted.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEYS:
                out[key] = "***REDACTED***"
            else:
                out[key] = redact_secrets(item)
        return out
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value

"""Redact secrets before writing tool args to evidence or playbook memory."""

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
    """Return a deep copy of ``value`` with secret-looking fields masked."""
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

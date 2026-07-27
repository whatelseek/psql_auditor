"""Redact secrets before writing tool args to evidence or playbook memory.

Pipeline role:
    Called by ``PlaybookMemory.remember_tool`` and evidence writers so SSH
    passwords, API tokens, and similar fields never land in JSON artifacts
    or long-term procedural memory. Also scans free-form stdout/stderr text.
"""

from __future__ import annotations

import re
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

_SECRET_TEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END [^-]+-----"
    ),
    re.compile(r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(ssh_password|winrm_password|pg_password)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)vault://\S+"),
    re.compile(r"(?i)secret_ref\s*[:=]\s*\S+"),
    re.compile(r"(?i)(postgresql|postgres|mysql)://[^\s]+"),
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


def redact_secret_text(text: str, *, known_secrets: list[str] | tuple[str, ...] = ()) -> str:
    """Mask secret-shaped substrings in free-form tool stdout/stderr.

    Args:
        text: Raw tool output text.
        known_secrets: Optional exact secret strings from the active run context
            (e.g. SSH password) that must never appear in evidence/LLM text.

    Returns:
        Text with matched patterns replaced by ``***REDACTED***``.
    """
    out = text or ""
    for secret in known_secrets:
        value = (secret or "").strip()
        if value and value in out:
            out = out.replace(value, "***REDACTED***")
    for pattern in _SECRET_TEXT_PATTERNS:
        out = pattern.sub("***REDACTED***", out)
    return out

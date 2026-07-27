"""Read-only SSH invocation policy (EVID-002).

Deterministic deny-list for destructive / mutating shell patterns. Registered
SSH tools must pass this gate before asyncssh is contacted.
"""

from __future__ import annotations

import re

# Conservative deny patterns for host shell commands (case-insensitive).
_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|--force\b)",
        r"\bmkfs(\.|$|\s)",
        r"\bdd\s+.*\bof=",
        r"\b(shutdown|reboot|poweroff|halt)\b",
        r"\buser(add|del|mod)\b",
        r"\bpasswd\b",
        r"\bchmod\s+(-R\s+)?777\b",
        r"\bchown\s+-R\b",
        r"\b(systemctl|service)\s+(stop|disable|mask|restart|start)\b",
        r"\b(apt|apt-get|yum|dnf|zypper)\s+(install|remove|purge|erase)\b",
        r"\bpip\s+(install|uninstall)\b",
        r"\b(curl|wget)\b.*\|\s*(sh|bash)\b",
        r">\s*/(etc|boot|usr)/",
        r"\btee\s+/",
        r"\btruncate\b",
        r"\b(shred|wipe)\b",
        r"\bcrontab\s+-r\b",
        r"\bkill\s+-9\b",
        r"\bmkfs\.",
        r"\bparted\b",
        r"\bfdisk\b",
    )
)


def is_readonly_ssh_command(command: str) -> bool:
    """Return True when ``command`` does not match known destructive patterns.

    Intentionally conservative — suitable as an auditor gate, not a full shell
    parser. Empty commands are rejected.
    """
    text = (command or "").strip()
    if not text:
        return False
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(text):
            return False
    return True


def readonly_ssh_denial_reason(command: str) -> str | None:
    """Return a short denial reason, or ``None`` when the command is allowed."""
    text = (command or "").strip()
    if not text:
        return "empty command"
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(text):
            return f"command matched destructive pattern: {pattern.pattern}"
    return None

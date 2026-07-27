"""Strict SSH invocation policy (EVID-002).

Registered SSH tools must match an approved command allow-list (or an approved
path for ``ssh_read_file``). Shell composition, redirects, and arbitrary
interpreters are rejected before asyncssh is contacted.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

# Shell composition / interpreter markers that are never allowed in ssh_run.
_COMPOSITION_RE = re.compile(
    r"""
    [|;`$]
    | &&
    | \|\|
    | \n
    | \r
    | (?<![\w.-])(?:bash|sh|zsh|ksh|dash|python(?:3)?|perl|ruby|node|osascript)\b
    | <\(
    | >\(
    | (?<![\w])(?:eval|exec|source|\.)\s
    """,
    re.IGNORECASE | re.VERBOSE,
)

_REDIRECT_RE = re.compile(r"(?:^|[\s])(?:>>?|<<?)\s")

# Exact commands and simple regex templates for approved read-only probes.
_EXACT_COMMANDS: frozenset[str] = frozenset(
    {
        "hostname",
        "uname -a",
        "uname -r",
        "uname -m",
        "cat /etc/os-release",
        "id",
        "whoami",
        "uptime",
        "df -h",
        "free -m",
        "ps -ef",
        "ps aux",
        "ss -lntp",
        "ss -lntup",
        "ss -lnt",
        "netstat -lntup",
        "netstat -lntp",
        "psql --version",
        "postgres --version",
        "command -v psql",
        "command -v postgres",
        "systemctl list-units --type=service --state=running --no-pager",
        "systemctl list-units --type=service --all --no-pager",
        "ls -ld /var/lib/postgresql",
        "ls -ld /var/lib/pgsql",
        "ls -ld /etc/postgresql",
    }
)

_TEMPLATE_COMMANDS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"^sysctl\s+[A-Za-z0-9._*-]+$",
        r"^getent\s+(passwd|group)\s+[A-Za-z0-9._-]+$",
        r"^systemctl\s+status\s+[A-Za-z0-9@._:-]+\s+--no-pager$",
        r"^systemctl\s+is-active\s+[A-Za-z0-9@._:-]+$",
        r"^systemctl\s+is-enabled\s+[A-Za-z0-9@._:-]+$",
        r"^ls\s+-l[aAd]*\s+/etc/postgresql(?:/[A-Za-z0-9._/-]+)?$",
        r"^ls\s+-l[aAd]*\s+/var/lib/postgresql(?:/[A-Za-z0-9._/-]+)?$",
        r"^ls\s+-l[aAd]*\s+/var/lib/pgsql(?:/[A-Za-z0-9._/-]+)?$",
        r"^stat\s+/etc/postgresql(?:/[A-Za-z0-9._/-]+)?$",
        r"^stat\s+/var/lib/postgresql(?:/[A-Za-z0-9._/-]+)?$",
        r"^stat\s+/etc/os-release$",
        r"^readlink\s+-f\s+/etc/postgresql(?:/[A-Za-z0-9._/-]+)?$",
        r"^dpkg-query\s+-W\s+[A-Za-z0-9._+-]+$",
        r"^rpm\s+-q\s+[A-Za-z0-9._+-]+$",
    )
)

# Paths ssh_read_file may open (prefix / exact). Traversal and blocked names rejected.
_APPROVED_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/os-release",
    "/etc/postgresql/",
    "/var/lib/pgsql/",
    "/var/lib/postgresql/",
    "/usr/share/postgresql/",
)

_APPROVED_PATH_EXACT: frozenset[str] = frozenset(
    {
        "/etc/os-release",
        "/etc/postgresql/postgresql.conf",
        "/var/lib/pgsql/data/postgresql.conf",
        "/var/lib/pgsql/data/pg_hba.conf",
        "/var/lib/pgsql/data/pg_ident.conf",
    }
)

_APPROVED_BASENAMES: frozenset[str] = frozenset(
    {
        "postgresql.conf",
        "pg_hba.conf",
        "pg_ident.conf",
        "pg_service.conf",
        "os-release",
    }
)

_BLOCKED_PATH_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"(^|/)\.ssh(/|$)",
        r"(^|/)id_rsa",
        r"(^|/)id_ed25519",
        r"(^|/)id_ecdsa",
        r"(^|/)id_dsa",
        r"(^|/)authorized_keys$",
        r"(^|/)known_hosts$",
        r"/etc/shadow",
        r"/etc/gshadow",
        r"/etc/sudoers",
        r"/etc/passwd$",  # use getent via ssh_run instead of raw file read
        r"/proc/\d+/environ",
        r"(password|passwd|credential|secret|token|private.?key)",
        r"\.pem$",
        r"\.key$",
        r"\.p12$",
        r"\.pfx$",
        r"connection\.md$",
        r"credentials\.md$",
    )
)


def _has_shell_composition(command: str) -> bool:
    if _COMPOSITION_RE.search(command):
        return True
    if _REDIRECT_RE.search(command):
        return True
    # Disallow variable expansion / globs outside approved templates.
    if "$" in command or "`" in command:
        return True
    return False


def is_approved_ssh_command(command: str) -> bool:
    """Return True when ``command`` matches the strict allow-list."""
    text = (command or "").strip()
    if not text:
        return False
    if _has_shell_composition(text):
        return False
    if text in _EXACT_COMMANDS:
        return True
    return any(pat.fullmatch(text) for pat in _TEMPLATE_COMMANDS)


def ssh_command_denial_reason(command: str) -> str | None:
    """Return a denial reason, or ``None`` when the command is approved."""
    text = (command or "").strip()
    if not text:
        return "empty command"
    if _has_shell_composition(text):
        return "shell composition, redirects, or interpreters are not allowed"
    if text in _EXACT_COMMANDS:
        return None
    if any(pat.fullmatch(text) for pat in _TEMPLATE_COMMANDS):
        return None
    return "command is not on the approved SSH allow-list"


# Back-compat aliases used by older imports/tests.
def is_readonly_ssh_command(command: str) -> bool:
    """Alias for :func:`is_approved_ssh_command` (allow-list based)."""
    return is_approved_ssh_command(command)


def readonly_ssh_denial_reason(command: str) -> str | None:
    """Alias for :func:`ssh_command_denial_reason`."""
    return ssh_command_denial_reason(command)


def _normalize_remote_path(path: str) -> str | None:
    text = (path or "").strip()
    if not text or "\x00" in text:
        return None
    if any(
        ch in text for ch in ("\n", "\r", "`", "$", ";", "|", "&", ">", "<", "*", "?", "[", "]")
    ):
        return None
    # Must be absolute POSIX path without traversal.
    if not text.startswith("/"):
        return None
    pure = PurePosixPath(text)
    if ".." in pure.parts:
        return None
    # Collapse // and resolve . segments without following symlinks conceptually.
    normalized = str(
        PurePosixPath("/") / PurePosixPath(*[p for p in pure.parts if p not in ("", ".")])
    )
    if normalized != "/" and text.endswith("/") and not normalized.endswith("/"):
        # Keep trailing slash only for directory prefixes we never approve as files.
        return None
    return normalized


def is_approved_ssh_read_path(path: str) -> bool:
    """Return True when ``path`` is an approved remote file for ``ssh_read_file``."""
    normalized = _normalize_remote_path(path)
    if normalized is None:
        return False
    for blocked in _BLOCKED_PATH_PATTERNS:
        if blocked.search(normalized):
            return False
    if normalized in _APPROVED_PATH_EXACT:
        return True
    basename = PurePosixPath(normalized).name
    if basename not in _APPROVED_BASENAMES:
        return False
    return any(
        normalized == prefix.rstrip("/") or normalized.startswith(prefix)
        for prefix in _APPROVED_PATH_PREFIXES
    )


def ssh_read_path_denial_reason(path: str) -> str | None:
    """Return a denial reason for ``ssh_read_file``, or ``None`` when approved."""
    text = (path or "").strip()
    if not text:
        return "empty path"
    normalized = _normalize_remote_path(path)
    if normalized is None:
        return "path must be an absolute POSIX path without traversal or shell metacharacters"
    for blocked in _BLOCKED_PATH_PATTERNS:
        if blocked.search(normalized):
            return f"path is blocked as sensitive: {normalized}"
    if is_approved_ssh_read_path(path):
        return None
    return f"path is not on the approved ssh_read_file allow-list: {normalized}"

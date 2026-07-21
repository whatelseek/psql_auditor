"""Shared read-only SQL gate for Postgres evidence collection.

The live auditor queries Postgres via LangChain MCP (``auditor.tools.mcp_client``).
This module only classifies SQL as read-only so MCP wrappers can reject mutations.
"""

from __future__ import annotations

# Statement-start verbs that must never run in the auditor.
_FORBIDDEN_PREFIXES = (
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "truncate",
    "grant",
    "revoke",
    "copy",
    "call",
    "do",
    "comment",
    "security",
    "reindex",
    "vacuum",
    "analyze",
    "cluster",
    "refresh",
    "listen",
    "notify",
)

# Allowed statement-start verbs for evidence collection.
_ALLOWED_PREFIXES = ("select", "show", "with", "table", "values", "explain")


def _strip_leading_comments(sql: str) -> str:
    """Remove leading ``--`` / ``/* */`` comments before classifying SQL."""
    text = sql.strip()
    while True:
        if text.startswith("--"):
            nl = text.find("\n")
            if nl < 0:
                return ""
            text = text[nl + 1 :].strip()
            continue
        if text.startswith("/*"):
            end = text.find("*/")
            if end < 0:
                return ""
            text = text[end + 2 :].strip()
            continue
        break
    return text


def is_readonly_sql(sql: str) -> bool:
    """Return True if every statement in ``sql`` looks read-only.

    Splits on ``;`` and requires each non-empty part to start with an allowed
    verb (including ``WITH`` CTEs) and not with a forbidden verb. Intentionally
    conservative — suitable for an auditor, not a full SQL parser.
    """
    lowered = " ".join(_strip_leading_comments(sql).lower().split())
    if not lowered:
        return False
    for part in lowered.split(";"):
        part = part.strip()
        if not part:
            continue
        if not part.startswith(_ALLOWED_PREFIXES):
            return False
        first = part.split(None, 1)[0]
        if first in _FORBIDDEN_PREFIXES:
            return False
    return True

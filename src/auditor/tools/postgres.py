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
    """Remove leading ``--`` and ``/* */`` comments before classifying SQL.

    Strips comment blocks from the start of the string only (not inline
    comments). Used so ``SELECT`` statements prefixed with header comments
    are still recognized as read-only.

    Args:
        sql: Raw SQL text, possibly with leading comments.

    Returns:
        SQL with leading comments removed, or an empty string if the input
        is only comments or an unclosed block comment.
    """
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
    verb (``SELECT``, ``SHOW``, ``WITH``, ``TABLE``, ``VALUES``, ``EXPLAIN``)
    and not with a forbidden verb. Intentionally conservative — suitable for
    an auditor gate, not a full SQL parser.

    Args:
        sql: One or more SQL statements (semicolon-separated).

    Returns:
        ``True`` when all non-empty statements pass the prefix checks;
        ``False`` for empty input, unknown verbs, or mutating prefixes.
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

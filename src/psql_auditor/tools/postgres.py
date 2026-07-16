"""Direct PostgreSQL SQL tools for audit queries.

Provides a read-only ``run_sql`` tool backed by ``asyncpg``. The auditor uses
this for ``SHOW`` settings and ``SELECT`` against catalogs such as
``pg_roles``, ``pg_extension``, and ``pg_settings``.

Safety: statements are gated by ``_is_readonly`` before execution. Mutating
SQL is rejected with an error string so the agent records ``status=error``
rather than changing the target database.
"""

from __future__ import annotations

import asyncpg
from langchain_core.tools import tool

from psql_auditor.config import Settings, get_settings

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
    """Remove leading ``--`` / ``/* */`` comments before classifying SQL.

    Args:
        sql: Raw SQL text from the model.

    Returns:
        SQL with leading comments stripped, or empty string if only comments.
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


def _is_readonly(sql: str) -> bool:
    """Return True if every statement in ``sql`` looks read-only.

    Splits on ``;`` and requires each non-empty part to start with an allowed
    verb and not with a forbidden verb. This is intentionally conservative
    (string/heuristic based) — suitable for an auditor, not a full SQL parser.

    Args:
        sql: Candidate SQL (may contain multiple statements).

    Returns:
        ``True`` if the batch appears safe to run; ``False`` otherwise.
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


async def _fetch(sql: str, settings: Settings | None = None) -> str:
    """Connect with asyncpg, run read-only SQL, and format rows as TSV text.

    Uses ``conn.fetch`` first. If that fails (some ``SHOW`` forms), retries with
    ``fetchval``. Caps output at 200 rows to keep tool messages small.

    Args:
        sql: Read-only SQL to execute.
        settings: Optional settings override for the DSN.

    Returns:
        Tab-separated result text, a ``value: …`` line, a configuration error,
        a read-only rejection message, or a ``PostgreSQL error: …`` string.
    """
    settings = settings or get_settings()
    dsn = settings.resolve_database_url()
    if not dsn:
        return (
            "PostgreSQL error: DATABASE_URL (or PG_HOST) is not configured. "
            "Set connection settings in the environment."
        )
    if not _is_readonly(sql):
        return (
            "PostgreSQL error: only read-only SQL is allowed "
            "(SELECT / SHOW / WITH … SELECT / EXPLAIN)."
        )
    try:
        conn = await asyncpg.connect(dsn=dsn, timeout=15)
        try:
            records = await conn.fetch(sql)
            if not records:
                return "rows: 0 (empty result)"
            columns = list(records[0].keys())
            lines = ["\t".join(columns)]
            for row in records[:200]:
                lines.append(
                    "\t".join("" if v is None else str(v) for v in row.values())
                )
            if len(records) > 200:
                lines.append(f"... truncated, total_rows={len(records)}")
            return "\n".join(lines)
        finally:
            await conn.close()
    except Exception as exc:  # noqa: BLE001
        # Fallback path for statements that don't return a record set cleanly.
        try:
            conn = await asyncpg.connect(dsn=dsn, timeout=15)
            try:
                value = await conn.fetchval(sql)
                return f"value: {value}"
            finally:
                await conn.close()
        except Exception:
            return f"PostgreSQL error: {type(exc).__name__}: {exc}"


@tool
async def run_sql(sql: str) -> str:
    """Run a read-only SQL statement against the configured PostgreSQL database.

    Prefer SHOW / SELECT against catalogs (pg_roles, pg_extension, pg_settings, etc.).
    Mutating statements are rejected.

    Args:
        sql: Read-only SQL (SELECT / SHOW / WITH … / EXPLAIN).

    Returns:
        Tabular text evidence or an error string describing why execution failed.
    """
    return await _fetch(sql)


def get_postgres_tools() -> list:
    """Return LangChain tools for direct PostgreSQL access.

    Returns:
        ``[run_sql]`` for binding into the assess model.
    """
    return [run_sql]

"""Direct PostgreSQL SQL tools for audit queries."""

from __future__ import annotations

import asyncpg
from langchain_core.tools import tool

from psql_auditor.config import Settings, get_settings

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

_ALLOWED_PREFIXES = ("select", "show", "with", "table", "values", "explain")


def _strip_leading_comments(sql: str) -> str:
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
    lowered = " ".join(_strip_leading_comments(sql).lower().split())
    if not lowered:
        return False
    for part in lowered.split(";"):
        part = part.strip()
        if not part:
            continue
        if not part.startswith(_ALLOWED_PREFIXES):
            return False
        # Reject stacked mutating statements after WITH/SELECT rarely needed —
        # still block obvious forbidden verbs as whole-statement starts.
        first = part.split(None, 1)[0]
        if first in _FORBIDDEN_PREFIXES:
            return False
    return True


async def _fetch(sql: str, settings: Settings | None = None) -> str:
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
    """
    return await _fetch(sql)


def get_postgres_tools() -> list:
    return [run_sql]

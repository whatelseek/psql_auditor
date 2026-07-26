"""PostgreSQL warehouse for numbered audit sessions (evidence stays on disk).

This module optionally persists **structured audit results** to PostgreSQL:
numbered sessions per client, host/framework result rows, checklist snapshots,
and filled requirement cells. Raw tool stdout remains on disk under
``artifacts/<client>/``.

Layout (when ``RESULTS_DB_PER_CLIENT=true``)::

    results_<client_slug>
      audit_sessions           -- session_number 1, 2, 3… per client
      hosts
      host_results             -- tagged with session_id + session_number
      framework_requirements   -- checklist snapshot for the session/framework
      requirement_results      -- filled cells (status/obs/rec)

Shared warehouse DB (``RESULTS_DATABASE_URL`` database, not per-client)::

    playbook_memory            -- learned procedural recipes (global)

Pipeline role:
    :func:`start_session_safe` allocates session numbers at intake;
    :func:`record_requirement_result_safe` dual-writes each filled REQ during
    assess; finalize and :func:`~auditor.followup.run_update_report` call
    :func:`record_results_safe` to refresh aggregates and mark completed.
    ``continue`` resumes the same session without a new number.

Key entry points:
    :class:`ResultsStore` — async PostgreSQL access and schema management.
    :func:`get_results_store` — singleton when ``RESULTS_DB_ENABLED``.
    :func:`resolve_continue_target` — map continue commands to thread/run/session.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse, urlunparse

import asyncpg

from auditor.compliance import findings_to_compliance_metrics
from auditor.checklist import Requirement
from auditor.config import Settings, get_settings
from auditor.domain.result_identity import (
    DuplicateLogicalKeyError,
    DuplicateResultIdError,
    logical_key_of,
    validate_result_identity,
)
from auditor.intake import client_slug as make_client_slug
from auditor.state import Finding

logger = logging.getLogger(__name__)

_SAFE_DB = re.compile(r"[^a-z0-9_]+")
_IP_LIKE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)$"
)


def _looks_like_ip(value: str) -> bool:
    """Return True when ``value`` looks like an IPv4/IPv6 address."""
    text = (value or "").strip()
    if not text or text == "_default":
        return False
    return bool(_IP_LIKE.match(text))

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_sessions (
    id                  bigserial PRIMARY KEY,
    session_number      int NOT NULL,
    client_name         text NOT NULL DEFAULT '',
    client_slug         text NOT NULL DEFAULT '',
    evidence_run_id     text NOT NULL DEFAULT '',
    status              text NOT NULL DEFAULT 'running',
    continue_thread_id  text NOT NULL DEFAULT '',
    pending_ids         jsonb NOT NULL DEFAULT '[]'::jsonb,
    framework_id        text NOT NULL DEFAULT '',
    report_language     text,
    evidence_path       text NOT NULL DEFAULT '',
    started_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    UNIQUE (client_slug, session_number)
);

CREATE INDEX IF NOT EXISTS audit_sessions_status_started_idx
    ON audit_sessions (status, started_at DESC);
CREATE INDEX IF NOT EXISTS audit_sessions_client_started_idx
    ON audit_sessions (client_slug, started_at DESC);

CREATE TABLE IF NOT EXISTS hosts (
    id              bigserial PRIMARY KEY,
    host_key        text NOT NULL,
    asset_id        text,
    ssh_host        text,
    hostname        text,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (host_key)
);

CREATE TABLE IF NOT EXISTS host_results (
    id              bigserial PRIMARY KEY,
    session_id      bigint NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
    session_number  int NOT NULL,
    host_id         bigint NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    framework_id    text NOT NULL,
    finished_at     timestamptz NOT NULL DEFAULT now(),
    source          text NOT NULL DEFAULT 'finalize',
    pass_count      int NOT NULL DEFAULT 0,
    fail_count      int NOT NULL DEFAULT 0,
    partial_count   int NOT NULL DEFAULT 0,
    error_count     int NOT NULL DEFAULT 0,
    skipped_count   int NOT NULL DEFAULT 0,
    assessed        int NOT NULL DEFAULT 0,
    compliance_pct  numeric(6,2) NOT NULL DEFAULT 0,
    evidence_relpath text NOT NULL DEFAULT '',
    report_relpath  text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS host_results_session_idx
    ON host_results (session_id, finished_at DESC);
CREATE INDEX IF NOT EXISTS host_results_host_finished_idx
    ON host_results (host_id, finished_at DESC);
CREATE INDEX IF NOT EXISTS host_results_framework_finished_idx
    ON host_results (framework_id, finished_at DESC);

CREATE TABLE IF NOT EXISTS framework_requirements (
    id              bigserial PRIMARY KEY,
    session_id      bigint NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
    session_number  int NOT NULL,
    framework_id    text NOT NULL,
    req_id          text NOT NULL,
    title           text NOT NULL DEFAULT '',
    category        text NOT NULL DEFAULT '',
    severity        text NOT NULL DEFAULT '',
    how_to_verify   text NOT NULL DEFAULT '',
    pass_criteria   text NOT NULL DEFAULT '',
    UNIQUE (session_id, framework_id, req_id)
);

CREATE TABLE IF NOT EXISTS requirement_results (
    id              bigserial PRIMARY KEY,
    host_result_id  bigint NOT NULL REFERENCES host_results(id) ON DELETE CASCADE,
    session_id      bigint NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
    session_number  int NOT NULL,
    req_id          text NOT NULL,
    title           text NOT NULL DEFAULT '',
    category        text NOT NULL DEFAULT '',
    severity        text NOT NULL DEFAULT '',
    status          text NOT NULL,
    pass_criteria   text NOT NULL DEFAULT '',
    how_to_verify   text NOT NULL DEFAULT '',
    observation     text NOT NULL DEFAULT '',
    recommendation  text NOT NULL DEFAULT '',
    notes           text NOT NULL DEFAULT '',
    -- CORE-003 canonical identity (mandatory for new writes)
    result_id       uuid,
    client_id       text,
    audit_run_id    text,
    asset_id        text,
    framework_id    text,
    framework_version text,
    UNIQUE (host_result_id, req_id)
);

CREATE INDEX IF NOT EXISTS requirement_results_session_idx
    ON requirement_results (session_id, req_id);
"""

# Shared warehouse DB (RESULTS_DATABASE_URL), not per-client — playbooks are global.
_PLAYBOOK_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS playbook_memory (
    framework_id    text NOT NULL,
    entry_key       text NOT NULL,
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    source          text NOT NULL DEFAULT 'learned',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (framework_id, entry_key)
);

CREATE INDEX IF NOT EXISTS playbook_memory_source_idx
    ON playbook_memory (source, updated_at DESC);
"""


@dataclass(frozen=True)
class AuditSessionInfo:
    """Allocated or loaded audit session in the results warehouse.

    Attributes:
        id: Primary key in ``audit_sessions``.
        session_number: Per-client monotonic session number (1, 2, 3…).
        client_name: Display client name.
        client_slug: Filesystem-safe client slug.
        evidence_run_id: Linked evidence folder name on disk.
        status: ``running``, ``interrupted``, or ``completed``.
        continue_thread_id: LangGraph thread for resume.
        framework_id: Active or last framework id.
        pending_ids: Remaining REQ ids when interrupted.
        started_at: Session start timestamp.
        finished_at: Set when status becomes terminal.
    """

    id: int
    session_number: int
    client_name: str
    client_slug: str
    evidence_run_id: str
    status: str
    continue_thread_id: str = ""
    framework_id: str = ""
    pending_ids: tuple[str, ...] = ()
    started_at: datetime | None = None
    finished_at: datetime | None = None


def sanitize_db_name(prefix: str, client_slug: str) -> str:
    """Build a PostgreSQL-safe database name: ``{prefix}{slug}``."""
    pref = _SAFE_DB.sub("_", (prefix or "results_").lower()).strip("_") or "results"
    slug = _SAFE_DB.sub("_", (client_slug or "client").lower()).strip("_") or "client"
    name = f"{pref}_{slug}" if not pref.endswith("_") else f"{pref}{slug}"
    return name[:63]


def _swap_database(dsn: str, database: str) -> str:
    """Return ``dsn`` with the path/database component replaced.

    Args:
        dsn: PostgreSQL connection URL.
        database: Target database name.

    Returns:
        DSN pointing at ``database``.
    """
    parsed = urlparse(dsn)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            f"/{database}",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _maintenance_dsn(dsn: str) -> str:
    """Connect to the server's maintenance DB (``postgres``) for CREATE DATABASE.

    Args:
        dsn: Base PostgreSQL connection URL.

    Returns:
        DSN with database set to ``postgres``.
    """
    return _swap_database(dsn, "postgres")


def _row_to_session(row: asyncpg.Record) -> AuditSessionInfo:
    """Convert an ``audit_sessions`` database row to :class:`AuditSessionInfo`.

    Args:
        row: asyncpg record from a session query.

    Returns:
        Populated :class:`AuditSessionInfo` instance.
    """
    pending_raw = row.get("pending_ids")
    pending: list[str] = []
    if isinstance(pending_raw, list):
        pending = [str(x) for x in pending_raw]
    elif isinstance(pending_raw, str) and pending_raw.strip():
        pending = [pending_raw]
    return AuditSessionInfo(
        id=int(row["id"]),
        session_number=int(row["session_number"]),
        client_name=str(row.get("client_name") or ""),
        client_slug=str(row.get("client_slug") or ""),
        evidence_run_id=str(row.get("evidence_run_id") or ""),
        status=str(row.get("status") or ""),
        continue_thread_id=str(row.get("continue_thread_id") or ""),
        framework_id=str(row.get("framework_id") or ""),
        pending_ids=tuple(pending),
        started_at=row.get("started_at"),
        finished_at=row.get("finished_at"),
    )


class ResultsStore:
    """Write numbered audit sessions + checklist cells into a results database.

    Creates per-client databases when ``RESULTS_DB_PER_CLIENT`` is enabled and
    ensures schema via :data:`_SCHEMA_SQL` on first connect.

    Attributes:
        settings: Auditor settings (DSN, feature flags, name prefix).
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize store with settings (defaults to :func:`~auditor.config.get_settings`).

        Args:
            settings: Optional settings override.
        """
        self.settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        """Return True when results DB is configured and enabled."""
        return bool(
            self.settings.results_db_enabled
            and (self.settings.results_database_url or "").strip()
        )

    def client_database_name(self, client_name: str) -> str:
        """Return PostgreSQL database name for a client.

        Args:
            client_name: Display client name.

        Returns:
            Sanitized ``{prefix}_{slug}`` name (max 63 chars).
        """
        slug = make_client_slug(client_name) or "client"
        return sanitize_db_name(self.settings.results_db_name_prefix, slug)

    async def start_session(
        self,
        *,
        client_name: str,
        evidence_run_id: str,
        continue_thread_id: str = "",
        framework_id: str = "",
        report_language: str | None = None,
        evidence_path: str = "",
    ) -> AuditSessionInfo | None:
        """Allocate the next ``session_number`` for this client (new audit).

        Inserts a row with status ``running`` and returns the allocated session.
        Does not run when the results DB is disabled.

        Args:
            client_name: Display client name.
            evidence_run_id: Linked evidence folder on disk.
            continue_thread_id: Initial LangGraph thread id.
            framework_id: First framework id when known.
            report_language: Report language code.
            evidence_path: Relative evidence path for the session.

        Returns:
            New :class:`AuditSessionInfo`, or ``None`` when disabled.
        """
        if not self.enabled:
            return None
        client = (client_name or evidence_run_id or "client").strip()
        slug = make_client_slug(client) or "client"
        run_id = (evidence_run_id or client).strip()
        dsn = await self._connect_dsn_for_client(slug)
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            async with conn.transaction():
                next_num = await conn.fetchval(
                    """
                    SELECT COALESCE(MAX(session_number), 0) + 1
                    FROM audit_sessions
                    WHERE client_slug = $1
                    """,
                    slug,
                )
                row = await conn.fetchrow(
                    """
                    INSERT INTO audit_sessions (
                        session_number, client_name, client_slug, evidence_run_id,
                        status, continue_thread_id, framework_id, report_language,
                        evidence_path, started_at
                    ) VALUES (
                        $1, $2, $3, $4, 'running', $5, $6, $7, $8, $9
                    )
                    RETURNING *
                    """,
                    int(next_num),
                    client,
                    slug,
                    run_id,
                    continue_thread_id or "",
                    framework_id or "",
                    report_language,
                    evidence_path or run_id,
                    datetime.now(timezone.utc),
                )
            info = _row_to_session(row)
            logger.info(
                "Results session #%s created for client %s (db id=%s)",
                info.session_number,
                slug,
                info.id,
            )
            return info
        finally:
            await conn.close()

    async def update_session_status(
        self,
        *,
        client_name: str,
        session_number: int,
        status: str,
        continue_thread_id: str | None = None,
        pending_ids: Sequence[str] | None = None,
        framework_id: str | None = None,
        evidence_run_id: str | None = None,
    ) -> None:
        """Update lifecycle fields for an existing session (running/interrupted/completed).

        Sets ``finished_at`` when status becomes ``completed`` or ``interrupted``;
        clears it when returning to ``running``.

        Args:
            client_name: Client display name (slug derived internally).
            session_number: Per-client session number to update.
            status: New status value.
            continue_thread_id: Optional new continue thread id.
            pending_ids: Optional replacement pending REQ id list.
            framework_id: Optional active framework id update.
            evidence_run_id: Optional evidence folder name (after client rename).
        """
        if not self.enabled:
            return
        slug = make_client_slug(client_name) or "client"
        dsn = await self._connect_dsn_for_client(slug)
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            finished = (
                datetime.now(timezone.utc)
                if status in {"completed", "interrupted"}
                else None
            )
            await conn.execute(
                """
                UPDATE audit_sessions SET
                    status = $3,
                    continue_thread_id = COALESCE($4, continue_thread_id),
                    pending_ids = COALESCE($5::jsonb, pending_ids),
                    framework_id = COALESCE(NULLIF($6, ''), framework_id),
                    evidence_run_id = COALESCE(NULLIF($8, ''), evidence_run_id),
                    finished_at = CASE
                        WHEN $7::timestamptz IS NOT NULL THEN $7
                        WHEN $3 = 'running' THEN NULL
                        ELSE finished_at
                    END
                WHERE client_slug = $1 AND session_number = $2
                """,
                slug,
                int(session_number),
                status,
                continue_thread_id,
                json.dumps(list(pending_ids)) if pending_ids is not None else None,
                framework_id,
                finished,
                evidence_run_id,
            )
        finally:
            await conn.close()

    async def get_session(
        self,
        *,
        client_name: str,
        session_number: int,
    ) -> AuditSessionInfo | None:
        """Load one audit session by client slug and session number.

        Args:
            client_name: Client display name (slug derived internally).
            session_number: Per-client session number.

        Returns:
            :class:`AuditSessionInfo` or ``None`` when not found or disabled.
        """
        if not self.enabled:
            return None
        slug = make_client_slug(client_name) or "client"
        dsn = await self._connect_dsn_for_client(slug)
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            row = await conn.fetchrow(
                """
                SELECT * FROM audit_sessions
                WHERE client_slug = $1 AND session_number = $2
                """,
                slug,
                int(session_number),
            )
            return _row_to_session(row) if row else None
        finally:
            await conn.close()

    async def get_latest_session(
        self,
        *,
        client_name: str,
        status: str | None = None,
    ) -> AuditSessionInfo | None:
        """Return the newest session for a client (optionally filtered by status)."""
        sessions = await self.list_sessions(
            client_name=client_name, status=status, limit=1
        )
        return sessions[0] if sessions else None

    async def list_session_requirement_results(
        self,
        *,
        client_name: str,
        session_number: int,
    ) -> tuple[AuditSessionInfo | None, list[dict[str, Any]], list[dict[str, Any]]]:
        """Load session meta, host aggregates, and REQ cells for one session.

        Args:
            client_name: Client display name (slug derived internally).
            session_number: Per-client session number.

        Returns:
            ``(session, host_rows, req_rows)``. Empty lists when missing/disabled.
        """
        if not self.enabled:
            return None, [], []
        info = await self.get_session(
            client_name=client_name, session_number=session_number
        )
        if info is None:
            return None, [], []
        slug = make_client_slug(client_name) or "client"
        dsn = await self._connect_dsn_for_client(slug)
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            host_rows = await conn.fetch(
                """
                SELECT hr.framework_id,
                       COALESCE(NULLIF(h.hostname, ''), NULLIF(h.ssh_host, ''),
                                h.host_key) AS host_label,
                       hr.pass_count, hr.fail_count, hr.partial_count,
                       hr.error_count, hr.skipped_count, hr.assessed,
                       hr.compliance_pct, hr.source, hr.finished_at,
                       hr.evidence_relpath
                FROM host_results hr
                JOIN hosts h ON h.id = hr.host_id
                WHERE hr.session_id = $1
                ORDER BY hr.framework_id, host_label
                """,
                info.id,
            )
            req_rows = await conn.fetch(
                """
                SELECT rr.req_id, rr.title, rr.category, rr.severity, rr.status,
                       rr.observation, rr.recommendation, rr.notes,
                       hr.framework_id,
                       COALESCE(NULLIF(h.hostname, ''), NULLIF(h.ssh_host, ''),
                                h.host_key) AS host_label
                FROM requirement_results rr
                JOIN host_results hr ON hr.id = rr.host_result_id
                JOIN hosts h ON h.id = hr.host_id
                WHERE rr.session_id = $1
                ORDER BY hr.framework_id, host_label, rr.req_id
                """,
                info.id,
            )
            return (
                info,
                [dict(r) for r in host_rows],
                [dict(r) for r in req_rows],
            )
        finally:
            await conn.close()

    async def list_session_host_status(
        self,
        *,
        client_name: str,
        session_number: int,
    ) -> tuple[AuditSessionInfo | None, list[dict[str, Any]]]:
        """Host/framework progress rows for ``/list-status`` (N/M ready).

        Args:
            client_name: Client display name.
            session_number: Per-client session number.

        Returns:
            ``(session, rows)`` where each row has hostname, ip, framework_id,
            filled, total, and ready_label.
        """
        if not self.enabled:
            return None, []
        info = await self.get_session(
            client_name=client_name, session_number=session_number
        )
        if info is None:
            return None, []
        slug = make_client_slug(client_name) or "client"
        dsn = await self._connect_dsn_for_client(slug)
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            rows = await conn.fetch(
                """
                SELECT
                    COALESCE(NULLIF(h.hostname, ''), h.host_key) AS hostname,
                    COALESCE(
                        NULLIF(h.ssh_host, ''),
                        CASE
                            WHEN h.host_key ~ '^[0-9a-fA-F:.]+$' THEN h.host_key
                            ELSE NULL
                        END,
                        '—'
                    ) AS ip,
                    hr.framework_id,
                    (
                        SELECT COUNT(*)::int FROM requirement_results rr
                        WHERE rr.host_result_id = hr.id
                    ) AS filled,
                    GREATEST(
                        (
                            SELECT COUNT(*)::int FROM framework_requirements fr
                            WHERE fr.session_id = hr.session_id
                              AND fr.framework_id = hr.framework_id
                        ),
                        (
                            SELECT COUNT(*)::int FROM requirement_results rr
                            WHERE rr.host_result_id = hr.id
                        )
                    ) AS total,
                    hr.source,
                    hr.finished_at
                FROM host_results hr
                JOIN hosts h ON h.id = hr.host_id
                WHERE hr.session_id = $1
                ORDER BY hostname, hr.framework_id
                """,
                info.id,
            )
            out: list[dict[str, Any]] = []
            for r in rows:
                filled = int(r["filled"] or 0)
                total = int(r["total"] or 0)
                row = dict(r)
                row["ready_label"] = f"{filled}/{total} ready" if total else f"{filled}/0 ready"
                out.append(row)
            return info, out
        finally:
            await conn.close()

    async def list_host_framework_results(
        self,
        *,
        hostname: str,
        framework_id: str,
        client_names: Sequence[str] | None = None,
        client_name: str | None = None,
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        """REQ cells for the newest host+framework match (``/list-host``).

        Searches known client warehouses when ``client_name`` is omitted.

        Args:
            hostname: Hostname, IP, or host_key fragment.
            framework_id: Framework id (exact or case-insensitive).
            client_names: Clients to scan when ``client_name`` is unset.
            client_name: Optional single-client filter.

        Returns:
            ``(meta, req_rows)`` where meta describes the matched host/session,
            or ``(None, [])`` when nothing matched.
        """
        if not self.enabled:
            return None, []
        needle = (hostname or "").strip()
        fw = (framework_id or "").strip()
        if not needle or not fw:
            return None, []
        clients: list[str] = []
        if client_name:
            clients = [client_name]
        elif client_names:
            clients = [c for c in client_names if c]
        if not clients and not self.settings.results_db_per_client:
            clients = ["shared"]
        if not clients:
            return None, []

        best_meta: dict[str, Any] | None = None
        best_reqs: list[dict[str, Any]] = []
        best_finished: datetime | None = None

        for name in clients:
            slug = make_client_slug(name) or "client"
            try:
                dsn = await self._connect_dsn_for_client(slug)
            except Exception as exc:  # noqa: BLE001
                logger.warning("list-host: cannot open DB for %s: %s", slug, exc)
                continue
            conn = await asyncpg.connect(dsn)
            try:
                await self._ensure_schema(conn)
                row = await conn.fetchrow(
                    """
                    SELECT hr.id AS host_result_id,
                           s.session_number,
                           s.client_name,
                           s.client_slug,
                           s.status AS session_status,
                           s.evidence_run_id,
                           hr.framework_id,
                           hr.finished_at,
                           hr.pass_count, hr.fail_count, hr.partial_count,
                           hr.error_count, hr.skipped_count, hr.assessed,
                           hr.compliance_pct,
                           COALESCE(NULLIF(h.hostname, ''), h.host_key) AS hostname,
                           COALESCE(NULLIF(h.ssh_host, ''), h.host_key) AS ip,
                           h.host_key
                    FROM host_results hr
                    JOIN hosts h ON h.id = hr.host_id
                    JOIN audit_sessions s ON s.id = hr.session_id
                    WHERE lower(hr.framework_id) = lower($1)
                      AND (
                            lower(h.host_key) = lower($2)
                         OR lower(COALESCE(h.hostname, '')) = lower($2)
                         OR lower(COALESCE(h.ssh_host, '')) = lower($2)
                         OR h.host_key ILIKE '%' || $2 || '%'
                         OR COALESCE(h.hostname, '') ILIKE '%' || $2 || '%'
                         OR COALESCE(h.ssh_host, '') ILIKE '%' || $2 || '%'
                      )
                    ORDER BY
                        CASE
                            WHEN lower(h.host_key) = lower($2) THEN 0
                            WHEN lower(COALESCE(h.hostname, '')) = lower($2) THEN 1
                            WHEN lower(COALESCE(h.ssh_host, '')) = lower($2) THEN 2
                            ELSE 3
                        END,
                        hr.finished_at DESC NULLS LAST,
                        hr.id DESC
                    LIMIT 1
                    """,
                    fw,
                    needle,
                )
                if row is None:
                    continue
                finished = row["finished_at"]
                if best_meta is not None and best_finished is not None:
                    if finished is None or finished < best_finished:
                        continue
                reqs = await conn.fetch(
                    """
                    SELECT rr.req_id, rr.title, rr.category, rr.severity, rr.status,
                           rr.observation, rr.recommendation, rr.notes
                    FROM requirement_results rr
                    WHERE rr.host_result_id = $1
                    ORDER BY rr.req_id
                    """,
                    int(row["host_result_id"]),
                )
                best_meta = dict(row)
                best_reqs = [dict(r) for r in reqs]
                best_finished = finished
            finally:
                await conn.close()

        return best_meta, best_reqs

    async def snapshot_framework_checklist(
        self,
        *,
        client_name: str,
        evidence_run_id: str,
        framework_id: str,
        requirements: Mapping[str, Requirement],
        evidence_host_id: str | None = None,
        session_number: int | None = None,
        hostname: str | None = None,
        ssh_host: str | None = None,
        evidence_relpath: str = "",
    ) -> None:
        """Upsert full checklist + empty host_results shell before assess.

        Ensures ``/list-status`` can show ``filled/total`` with the expected
        requirement count while cells are still being filled live.

        Args:
            client_name: Client display name.
            evidence_run_id: Evidence folder name.
            framework_id: Framework key.
            requirements: Full checklist map.
            evidence_host_id: Host slug / key.
            session_number: Explicit session when known.
            hostname: Resolved hostname when known.
            ssh_host: SSH target / IP when known.
            evidence_relpath: Relative evidence path.
        """
        if not self.enabled or not requirements:
            return
        client = (client_name or evidence_run_id or "client").strip()
        run_id = (evidence_run_id or "").strip() or make_client_slug(client)
        fw = (framework_id or "").strip() or "framework"
        if "/" in fw:
            host_from_key, bare = fw.split("/", 1)
            fw = bare or fw
            if not evidence_host_id:
                evidence_host_id = host_from_key
        host_key = (evidence_host_id or "").strip() or "_default"
        slug = make_client_slug(client)
        dsn = await self._connect_dsn_for_client(slug)
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            async with conn.transaction():
                sess = await self._resolve_session_row(
                    conn,
                    slug=slug,
                    client=client,
                    run_id=run_id,
                    session_number=session_number,
                    report_language=None,
                    evidence_path=evidence_relpath or run_id,
                    framework_id=fw,
                )
                session_pk = int(sess["id"])
                sess_num = int(sess["session_number"])
                host_pk = await self._upsert_host_identity(
                    conn,
                    host_key=host_key,
                    hostname=hostname,
                    ssh_host=ssh_host,
                )
                for req in requirements.values():
                    await conn.execute(
                        """
                        INSERT INTO framework_requirements (
                            session_id, session_number, framework_id, req_id,
                            title, category, severity, how_to_verify, pass_criteria
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                        ON CONFLICT (session_id, framework_id, req_id) DO UPDATE SET
                            title = EXCLUDED.title,
                            category = EXCLUDED.category,
                            severity = EXCLUDED.severity,
                            how_to_verify = EXCLUDED.how_to_verify,
                            pass_criteria = EXCLUDED.pass_criteria,
                            session_number = EXCLUDED.session_number
                        """,
                        session_pk,
                        sess_num,
                        fw,
                        req.id,
                        req.title or "",
                        req.category or "",
                        req.severity or "",
                        req.how_to_verify or "",
                        req.pass_criteria or "",
                    )
                empty_metrics = {
                    "pass": 0,
                    "fail": 0,
                    "partial": 0,
                    "error": 0,
                    "skipped": 0,
                    "assessed": 0,
                    "compliance_pct": 0.0,
                }
                await self._upsert_host_result_row(
                    conn,
                    session_pk=session_pk,
                    sess_num=sess_num,
                    host_pk=int(host_pk),
                    framework_id=fw,
                    source="assess_start",
                    metrics=empty_metrics,
                    evidence_relpath=evidence_relpath or run_id,
                    report_relpath="",
                    preserve_metrics_on_conflict=True,
                )
        finally:
            await conn.close()

    async def _upsert_host_identity(
        self,
        conn: asyncpg.Connection,
        *,
        host_key: str,
        hostname: str | None = None,
        ssh_host: str | None = None,
        asset_id: str | None = None,
    ) -> int:
        """Insert/update ``hosts`` row, preferring real hostname/IP when given.

        ``asset_id`` is the stable CORE-003 identity; ``ssh_host`` may change.
        """
        key = (host_key or "").strip() or "_default"
        hn = (hostname or "").strip() or None
        ip = (ssh_host or "").strip() or None
        aid = (asset_id or "").strip() or None
        if key != "_default":
            if hn is None and not _looks_like_ip(key):
                hn = key
            if ip is None and _looks_like_ip(key):
                ip = key
        return int(
            await conn.fetchval(
                """
                INSERT INTO hosts (host_key, asset_id, ssh_host, hostname, last_seen_at)
                VALUES ($1, $2, $3, $4, now())
                ON CONFLICT (host_key) DO UPDATE SET
                    last_seen_at = now(),
                    asset_id = COALESCE(EXCLUDED.asset_id, hosts.asset_id),
                    ssh_host = COALESCE(EXCLUDED.ssh_host, hosts.ssh_host),
                    hostname = COALESCE(EXCLUDED.hostname, hosts.hostname)
                RETURNING id
                """,
                key,
                aid,
                ip,
                hn,
            )
        )

    async def list_sessions(
        self,
        *,
        client_name: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[AuditSessionInfo]:
        """List sessions for one client DB, newest first.

        When ``RESULTS_DB_PER_CLIENT`` and ``client_name`` is empty, returns [].
        Callers that need a multi-client view should pass each known client.
        """
        if not self.enabled:
            return []
        if self.settings.results_db_per_client and not (client_name or "").strip():
            return []
        slug = make_client_slug(client_name or "shared") or "client"
        try:
            dsn = await self._connect_dsn_for_client(slug)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot open results DB for %s: %s", slug, exc)
            return []
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            if status:
                rows = await conn.fetch(
                    """
                    SELECT * FROM audit_sessions
                    WHERE ($1::text IS NULL OR client_slug = $1)
                      AND status = $2
                    ORDER BY started_at DESC
                    LIMIT $3
                    """,
                    slug if client_name else None,
                    status,
                    int(limit),
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT * FROM audit_sessions
                    WHERE ($1::text IS NULL OR client_slug = $1)
                    ORDER BY started_at DESC
                    LIMIT $2
                    """,
                    slug if client_name else None,
                    int(limit),
                )
            return [_row_to_session(r) for r in rows]
        finally:
            await conn.close()

    async def list_interrupted_across_clients(
        self,
        client_names: Sequence[str],
        *,
        limit_per_client: int = 5,
    ) -> list[AuditSessionInfo]:
        """Collect interrupted sessions for known client folders."""
        out: list[AuditSessionInfo] = []
        for name in client_names:
            found = await self.list_sessions(
                client_name=name, status="interrupted", limit=limit_per_client
            )
            out.extend(found)
        out.sort(
            key=lambda s: s.started_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        return out

    async def record_host_framework_audit(
        self,
        *,
        client_name: str,
        evidence_run_id: str,
        framework_id: str,
        evidence_host_id: str | None,
        findings: Mapping[str, Finding],
        requirements: Mapping[str, Requirement] | None = None,
        evidence_relpath: str = "",
        source: str = "finalize",
        report_language: str | None = None,
        session_number: int | None = None,
    ) -> None:
        """Insert timestamped host results + cells for a known session number.

        Upserts host row, framework requirement snapshots, per-REQ results,
        and aggregate metrics. Marks session completed when ``source`` is
        ``finalize`` or ``update_report``.

        Args:
            client_name: Client display name.
            evidence_run_id: Evidence folder name on disk.
            framework_id: Framework key (may be ``host/fw``).
            evidence_host_id: Host slug for multi-host runs.
            findings: Filled findings keyed by requirement id.
            requirements: Optional checklist snapshot.
            evidence_relpath: Relative path to evidence root.
            source: Write origin (``finalize``, ``update_report``, …).
            report_language: Report language code.
            session_number: Explicit session from run meta when known.
        """
        if not self.enabled:
            return
        if not findings and not requirements:
            return
        client = (client_name or evidence_run_id or "client").strip()
        run_id = (evidence_run_id or "").strip() or make_client_slug(client)
        fw = (framework_id or "").strip() or "framework"
        if "/" in fw:
            host_from_key, bare = fw.split("/", 1)
            fw = bare or fw
            if not evidence_host_id:
                evidence_host_id = host_from_key
        host_key = (evidence_host_id or "").strip() or "_default"
        slug = make_client_slug(client)

        dsn = await self._connect_dsn_for_client(slug)
        metrics = findings_to_compliance_metrics(findings) if findings else {
            "pass": 0,
            "fail": 0,
            "partial": 0,
            "error": 0,
            "skipped": 0,
            "assessed": 0,
            "compliance_pct": 0.0,
        }
        report_rel = ""
        if evidence_relpath:
            if host_key != "_default":
                report_rel = f"{evidence_relpath.rstrip('/')}/{host_key}/{fw}/report.md"
            else:
                report_rel = f"{evidence_relpath.rstrip('/')}/{fw}/report.md"

        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            async with conn.transaction():
                sess = await self._resolve_session_row(
                    conn,
                    slug=slug,
                    client=client,
                    run_id=run_id,
                    session_number=session_number,
                    report_language=report_language,
                    evidence_path=evidence_relpath or run_id,
                    framework_id=fw,
                )
                session_pk = int(sess["id"])
                sess_num = int(sess["session_number"])

                sample_asset = ""
                for f in findings.values():
                    if getattr(f, "asset_id", ""):
                        sample_asset = str(f.asset_id)
                        break
                host_pk = await self._upsert_host_identity(
                    conn,
                    host_key=host_key,
                    hostname=None,
                    ssh_host=None,
                    asset_id=sample_asset or None,
                )
                if requirements:
                    for req in requirements.values():
                        await conn.execute(
                            """
                            INSERT INTO framework_requirements (
                                session_id, session_number, framework_id, req_id,
                                title, category, severity, how_to_verify, pass_criteria
                            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                            ON CONFLICT (session_id, framework_id, req_id) DO UPDATE SET
                                title = EXCLUDED.title,
                                category = EXCLUDED.category,
                                severity = EXCLUDED.severity,
                                how_to_verify = EXCLUDED.how_to_verify,
                                pass_criteria = EXCLUDED.pass_criteria,
                                session_number = EXCLUDED.session_number
                            """,
                            session_pk,
                            sess_num,
                            fw,
                            req.id,
                            req.title or "",
                            req.category or "",
                            req.severity or "",
                            req.how_to_verify or "",
                            req.pass_criteria or "",
                        )
                hr_pk = await self._upsert_host_result_row(
                    conn,
                    session_pk=session_pk,
                    sess_num=sess_num,
                    host_pk=int(host_pk),
                    framework_id=fw,
                    source=source,
                    metrics=metrics,
                    evidence_relpath=evidence_relpath or run_id,
                    report_relpath=report_rel,
                )
                req_map = requirements or {}
                for finding in findings.values():
                    f = finding if isinstance(finding, Finding) else Finding.model_validate(finding)
                    req = req_map.get(f.requirement_id) if req_map else None
                    await self._upsert_requirement_cell(
                        conn,
                        host_result_id=hr_pk,
                        session_pk=session_pk,
                        sess_num=sess_num,
                        finding=f,
                        requirement=req,
                    )
                # Mark completed when finalize/update_report writes results.
                if source in {"finalize", "update_report"}:
                    await conn.execute(
                        """
                        UPDATE audit_sessions SET
                            status = 'completed',
                            finished_at = now(),
                            report_language = COALESCE($3, report_language),
                            framework_id = COALESCE(NULLIF($4, ''), framework_id)
                        WHERE id = $1 AND session_number = $2
                        """,
                        session_pk,
                        sess_num,
                        report_language,
                        fw,
                    )
        finally:
            await conn.close()

    async def upsert_requirement_result(
        self,
        *,
        client_name: str,
        evidence_run_id: str,
        framework_id: str,
        evidence_host_id: str | None,
        finding: Finding,
        requirement: Requirement | None = None,
        evidence_relpath: str = "",
        source: str = "live",
        session_number: int | None = None,
        hostname: str | None = None,
        ssh_host: str | None = None,
    ) -> None:
        """Upsert one filled REQ cell during assess (does not complete session).

        Creates or reuses the session's host_results row for
        ``(session, host, framework)``, writes the cell, and refreshes
        aggregate metrics from all cells for that host result.

        Args:
            client_name: Client display name.
            evidence_run_id: Evidence folder name on disk.
            framework_id: Framework key (may be ``host/fw``).
            evidence_host_id: Host slug for multi-host runs.
            finding: Filled finding for one requirement.
            requirement: Optional checklist row for metadata.
            evidence_relpath: Relative path to evidence root.
            source: Write origin (``live``, ``refill``, …).
            session_number: Explicit session from run meta when known.
            hostname: Resolved hostname when known.
            ssh_host: SSH target / IP when known.
        """
        if not self.enabled:
            return
        client = (client_name or evidence_run_id or "client").strip()
        run_id = (evidence_run_id or "").strip() or make_client_slug(client)
        fw = (framework_id or "").strip() or "framework"
        if "/" in fw:
            host_from_key, bare = fw.split("/", 1)
            fw = bare or fw
            if not evidence_host_id:
                evidence_host_id = host_from_key
        host_key = (evidence_host_id or "").strip() or "_default"
        slug = make_client_slug(client)

        dsn = await self._connect_dsn_for_client(slug)
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
            async with conn.transaction():
                sess = await self._resolve_session_row(
                    conn,
                    slug=slug,
                    client=client,
                    run_id=run_id,
                    session_number=session_number,
                    report_language=None,
                    evidence_path=evidence_relpath or run_id,
                    framework_id=fw,
                )
                session_pk = int(sess["id"])
                sess_num = int(sess["session_number"])

                host_pk = await self._upsert_host_identity(
                    conn,
                    host_key=host_key,
                    hostname=hostname,
                    ssh_host=ssh_host,
                    asset_id=str(finding.asset_id or "") or None,
                )
                if requirement is not None:
                    await conn.execute(
                        """
                        INSERT INTO framework_requirements (
                            session_id, session_number, framework_id, req_id,
                            title, category, severity, how_to_verify, pass_criteria
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                        ON CONFLICT (session_id, framework_id, req_id) DO UPDATE SET
                            title = EXCLUDED.title,
                            category = EXCLUDED.category,
                            severity = EXCLUDED.severity,
                            how_to_verify = EXCLUDED.how_to_verify,
                            pass_criteria = EXCLUDED.pass_criteria,
                            session_number = EXCLUDED.session_number
                        """,
                        session_pk,
                        sess_num,
                        fw,
                        requirement.id,
                        requirement.title or "",
                        requirement.category or "",
                        requirement.severity or "",
                        requirement.how_to_verify or "",
                        requirement.pass_criteria or "",
                    )

                empty_metrics = {
                    "pass": 0,
                    "fail": 0,
                    "partial": 0,
                    "error": 0,
                    "skipped": 0,
                    "assessed": 0,
                    "compliance_pct": 0.0,
                }
                hr_pk = await self._upsert_host_result_row(
                    conn,
                    session_pk=session_pk,
                    sess_num=sess_num,
                    host_pk=int(host_pk),
                    framework_id=fw,
                    source=source,
                    metrics=empty_metrics,
                    evidence_relpath=evidence_relpath or run_id,
                    report_relpath="",
                    preserve_metrics_on_conflict=True,
                )
                await self._upsert_requirement_cell(
                    conn,
                    host_result_id=hr_pk,
                    session_pk=session_pk,
                    sess_num=sess_num,
                    finding=finding,
                    requirement=requirement,
                )
                await self._refresh_host_result_metrics(conn, hr_pk)
                await conn.execute(
                    """
                    UPDATE audit_sessions SET
                        framework_id = COALESCE(NULLIF($2, ''), framework_id)
                    WHERE id = $1 AND status IN ('running', 'interrupted')
                    """,
                    session_pk,
                    fw,
                )
        finally:
            await conn.close()

    async def _upsert_host_result_row(
        self,
        conn: asyncpg.Connection,
        *,
        session_pk: int,
        sess_num: int,
        host_pk: int,
        framework_id: str,
        source: str,
        metrics: Mapping[str, Any],
        evidence_relpath: str,
        report_relpath: str,
        preserve_metrics_on_conflict: bool = False,
    ) -> int:
        """Insert or update the single host_results row for session/host/fw.

        Args:
            conn: Open connection (within transaction).
            session_pk: ``audit_sessions.id``.
            sess_num: Session number.
            host_pk: ``hosts.id``.
            framework_id: Bare framework id.
            source: Write origin label.
            metrics: Aggregate counters (ignored on conflict when preserving).
            evidence_relpath: Evidence path for the row.
            report_relpath: Report path (may be empty during live writes).
            preserve_metrics_on_conflict: When True, keep existing aggregates
                until :meth:`_refresh_host_result_metrics` runs.

        Returns:
            ``host_results.id``.
        """
        if preserve_metrics_on_conflict:
            return int(
                await conn.fetchval(
                    """
                    INSERT INTO host_results (
                        session_id, session_number, host_id, framework_id,
                        finished_at, source,
                        pass_count, fail_count, partial_count, error_count,
                        skipped_count, assessed, compliance_pct,
                        evidence_relpath, report_relpath
                    ) VALUES (
                        $1,$2,$3,$4,now(),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
                    )
                    ON CONFLICT (session_id, host_id, framework_id) DO UPDATE SET
                        finished_at = now(),
                        source = EXCLUDED.source,
                        session_number = EXCLUDED.session_number,
                        evidence_relpath = COALESCE(
                            NULLIF(EXCLUDED.evidence_relpath, ''),
                            host_results.evidence_relpath
                        ),
                        report_relpath = COALESCE(
                            NULLIF(EXCLUDED.report_relpath, ''),
                            host_results.report_relpath
                        )
                    RETURNING id
                    """,
                    session_pk,
                    sess_num,
                    host_pk,
                    framework_id,
                    source,
                    int(metrics.get("pass", 0)),
                    int(metrics.get("fail", 0)),
                    int(metrics.get("partial", 0)),
                    int(metrics.get("error", 0)),
                    int(metrics.get("skipped", 0)),
                    int(metrics.get("assessed", 0)),
                    float(metrics.get("compliance_pct", 0.0)),
                    evidence_relpath,
                    report_relpath,
                )
            )
        return int(
            await conn.fetchval(
                """
                INSERT INTO host_results (
                    session_id, session_number, host_id, framework_id,
                    finished_at, source,
                    pass_count, fail_count, partial_count, error_count,
                    skipped_count, assessed, compliance_pct,
                    evidence_relpath, report_relpath
                ) VALUES (
                    $1,$2,$3,$4,now(),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
                )
                ON CONFLICT (session_id, host_id, framework_id) DO UPDATE SET
                    finished_at = now(),
                    source = EXCLUDED.source,
                    session_number = EXCLUDED.session_number,
                    pass_count = EXCLUDED.pass_count,
                    fail_count = EXCLUDED.fail_count,
                    partial_count = EXCLUDED.partial_count,
                    error_count = EXCLUDED.error_count,
                    skipped_count = EXCLUDED.skipped_count,
                    assessed = EXCLUDED.assessed,
                    compliance_pct = EXCLUDED.compliance_pct,
                    evidence_relpath = COALESCE(
                        NULLIF(EXCLUDED.evidence_relpath, ''),
                        host_results.evidence_relpath
                    ),
                    report_relpath = COALESCE(
                        NULLIF(EXCLUDED.report_relpath, ''),
                        host_results.report_relpath
                    )
                RETURNING id
                """,
                session_pk,
                sess_num,
                host_pk,
                framework_id,
                source,
                int(metrics.get("pass", 0)),
                int(metrics.get("fail", 0)),
                int(metrics.get("partial", 0)),
                int(metrics.get("error", 0)),
                int(metrics.get("skipped", 0)),
                int(metrics.get("assessed", 0)),
                float(metrics.get("compliance_pct", 0.0)),
                evidence_relpath,
                report_relpath,
            )
        )

    async def _upsert_requirement_cell(
        self,
        conn: asyncpg.Connection,
        *,
        host_result_id: int,
        session_pk: int,
        sess_num: int,
        finding: Finding,
        requirement: Requirement | None,
    ) -> None:
        """Upsert one requirement_results row for a host result.

        Enforces CORE-003 identity at the application boundary before write.
        Same ``result_id`` + same logical key may update content; conflicts raise.
        """
        validate_result_identity(finding, for_persist=True)
        key = logical_key_of(finding)
        existing_by_id = await conn.fetchrow(
            """
            SELECT result_id, client_id, audit_run_id, asset_id,
                   framework_id, framework_version, req_id
            FROM requirement_results
            WHERE result_id = $1::uuid
            """,
            finding.result_id,
        )
        if existing_by_id is not None:
            prev = {
                "client_id": str(existing_by_id["client_id"] or ""),
                "audit_run_id": str(existing_by_id["audit_run_id"] or ""),
                "asset_id": str(existing_by_id["asset_id"] or ""),
                "framework_id": str(existing_by_id["framework_id"] or ""),
                "framework_version": str(existing_by_id["framework_version"] or ""),
                "requirement_id": str(existing_by_id["req_id"] or ""),
            }
            if (
                prev["client_id"]
                and prev["audit_run_id"]
                and prev["asset_id"]
                and prev["framework_id"]
                and prev["framework_version"]
                and logical_key_of(prev).as_tuple() != key.as_tuple()
            ):
                raise DuplicateResultIdError(
                    f"duplicate result_id {finding.result_id!r} with conflicting "
                    f"logical keys: {prev} vs {key.as_dict()}"
                )
        existing_by_key = await conn.fetchrow(
            """
            SELECT result_id FROM requirement_results
            WHERE client_id = $1
              AND audit_run_id = $2
              AND asset_id = $3
              AND framework_id = $4
              AND framework_version = $5
              AND req_id = $6
            """,
            key.client_id,
            key.audit_run_id,
            key.asset_id,
            key.framework_id,
            key.framework_version,
            key.requirement_id,
        )
        if (
            existing_by_key is not None
            and str(existing_by_key["result_id"] or "") != finding.result_id
        ):
            raise DuplicateLogicalKeyError(
                key,
                existing_result_id=str(existing_by_key["result_id"] or ""),
                new_result_id=finding.result_id,
            )
        await conn.execute(
            """
            INSERT INTO requirement_results (
                host_result_id, session_id, session_number,
                req_id, title, category, severity,
                status, pass_criteria, how_to_verify,
                observation, recommendation, notes,
                result_id, client_id, audit_run_id, asset_id,
                framework_id, framework_version
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
                $14::uuid,$15,$16,$17,$18,$19
            )
            ON CONFLICT (host_result_id, req_id) DO UPDATE SET
                title = EXCLUDED.title,
                category = EXCLUDED.category,
                severity = EXCLUDED.severity,
                status = EXCLUDED.status,
                pass_criteria = EXCLUDED.pass_criteria,
                how_to_verify = EXCLUDED.how_to_verify,
                observation = EXCLUDED.observation,
                recommendation = EXCLUDED.recommendation,
                notes = EXCLUDED.notes,
                session_id = EXCLUDED.session_id,
                session_number = EXCLUDED.session_number,
                result_id = EXCLUDED.result_id,
                client_id = EXCLUDED.client_id,
                audit_run_id = EXCLUDED.audit_run_id,
                asset_id = EXCLUDED.asset_id,
                framework_id = EXCLUDED.framework_id,
                framework_version = EXCLUDED.framework_version
            WHERE requirement_results.result_id IS NULL
               OR requirement_results.result_id = EXCLUDED.result_id
            """,
            host_result_id,
            session_pk,
            sess_num,
            finding.requirement_id,
            finding.title or (requirement.title if requirement else ""),
            finding.category or (requirement.category if requirement else ""),
            finding.severity or (requirement.severity if requirement else ""),
            finding.status,
            finding.pass_criteria
            or (requirement.pass_criteria if requirement else ""),
            (requirement.how_to_verify if requirement else ""),
            finding.evidence or "",
            finding.remediation or "",
            finding.notes or "",
            finding.result_id,
            finding.client_id,
            finding.audit_run_id,
            finding.asset_id,
            finding.framework_id,
            finding.framework_version,
        )

    async def _refresh_host_result_metrics(
        self,
        conn: asyncpg.Connection,
        host_result_id: int,
    ) -> None:
        """Recompute host_results aggregates from requirement_results cells."""
        rows = await conn.fetch(
            """
            SELECT result_id, req_id, status, title, severity,
                   client_id, audit_run_id, asset_id, framework_id, framework_version
            FROM requirement_results
            WHERE host_result_id = $1
            """,
            host_result_id,
        )
        valid = {"pass", "fail", "partial", "error", "skipped"}
        findings: dict[str, Finding] = {}
        for r in rows:
            status = str(r["status"] or "error").lower()
            if status not in valid:
                status = "error"
            req_id = str(r["req_id"] or "")
            result_id = str(r["result_id"] or "") or req_id
            findings[result_id] = Finding(
                requirement_id=req_id,
                title=str(r["title"] or ""),
                status=status,  # type: ignore[arg-type]
                severity=str(r["severity"] or ""),
                result_id=str(r["result_id"] or ""),
                client_id=str(r["client_id"] or ""),
                audit_run_id=str(r["audit_run_id"] or ""),
                asset_id=str(r["asset_id"] or ""),
                framework_id=str(r["framework_id"] or ""),
                framework_version=str(r["framework_version"] or ""),
            )
        metrics = findings_to_compliance_metrics(findings) if findings else {
            "pass": 0,
            "fail": 0,
            "partial": 0,
            "error": 0,
            "skipped": 0,
            "assessed": 0,
            "compliance_pct": 0.0,
        }
        await conn.execute(
            """
            UPDATE host_results SET
                pass_count = $2,
                fail_count = $3,
                partial_count = $4,
                error_count = $5,
                skipped_count = $6,
                assessed = $7,
                compliance_pct = $8,
                finished_at = now()
            WHERE id = $1
            """,
            host_result_id,
            int(metrics.get("pass", 0)),
            int(metrics.get("fail", 0)),
            int(metrics.get("partial", 0)),
            int(metrics.get("error", 0)),
            int(metrics.get("skipped", 0)),
            int(metrics.get("assessed", 0)),
            float(metrics.get("compliance_pct", 0.0)),
        )

    async def _resolve_session_row(
        self,
        conn: asyncpg.Connection,
        *,
        slug: str,
        client: str,
        run_id: str,
        session_number: int | None,
        report_language: str | None,
        evidence_path: str,
        framework_id: str,
    ) -> asyncpg.Record:
        """Resolve or create ``audit_sessions`` row for a results write.

        Prefers explicit ``session_number``, then latest running/interrupted
        session, then creates session #1 as last resort.

        Args:
            conn: Open database connection (within transaction).
            slug: Client slug.
            client: Display client name.
            run_id: Evidence run id on disk.
            session_number: Explicit session from run meta, if any.
            report_language: Report language code.
            evidence_path: Relative evidence path.
            framework_id: Framework being recorded.

        Returns:
            asyncpg record for the resolved session row.
        """
        if session_number is not None:
            row = await conn.fetchrow(
                """
                SELECT * FROM audit_sessions
                WHERE client_slug = $1 AND session_number = $2
                """,
                slug,
                int(session_number),
            )
            if row:
                return row
        # Prefer latest running, else latest any for this client.
        row = await conn.fetchrow(
            """
            SELECT * FROM audit_sessions
            WHERE client_slug = $1
            ORDER BY
                CASE WHEN status = 'running' THEN 0
                     WHEN status = 'interrupted' THEN 1
                     ELSE 2 END,
                started_at DESC
            LIMIT 1
            """,
            slug,
        )
        if row:
            return row
        # Last resort: create session #1 so finalize still works if start was skipped.
        next_num = 1
        return await conn.fetchrow(
            """
            INSERT INTO audit_sessions (
                session_number, client_name, client_slug, evidence_run_id,
                status, framework_id, report_language, evidence_path, started_at
            ) VALUES ($1,$2,$3,$4,'running',$5,$6,$7,$8)
            RETURNING *
            """,
            next_num,
            client,
            slug,
            run_id,
            framework_id,
            report_language,
            evidence_path,
            datetime.now(timezone.utc),
        )

    async def _connect_dsn_for_client(self, client_slug: str) -> str:
        """Return connection DSN for shared or per-client results database.

        Creates the client database and schema when needed.

        Args:
            client_slug: Client slug for per-client DB naming.

        Returns:
            Connection URL ready for :func:`asyncpg.connect`.

        Raises:
            RuntimeError: When ``RESULTS_DATABASE_URL`` is empty.
        """
        base = (self.settings.results_database_url or "").strip()
        if not base:
            raise RuntimeError("RESULTS_DATABASE_URL is empty")
        if not self.settings.results_db_per_client:
            await self._ensure_schema_on_dsn(base)
            return base
        db_name = self.client_database_name(client_slug)
        await self._ensure_database_exists(base, db_name)
        client_dsn = _swap_database(base, db_name)
        await self._ensure_schema_on_dsn(client_dsn)
        return client_dsn

    async def _ensure_database_exists(self, admin_dsn: str, db_name: str) -> None:
        """Create per-client results database if it does not exist.

        Args:
            admin_dsn: Connection URL to maintenance ``postgres`` database.
            db_name: Target database name to create.
        """
        maint = _maintenance_dsn(admin_dsn)
        conn = await asyncpg.connect(maint)
        try:
            exists = await conn.fetchval(
                "SELECT 1 FROM pg_database WHERE datname = $1", db_name
            )
            if not exists:
                await conn.execute(f'CREATE DATABASE "{db_name}"')
                logger.info("Created results database %s", db_name)
        finally:
            await conn.close()

    async def _ensure_schema_on_dsn(self, dsn: str) -> None:
        """Apply :data:`_SCHEMA_SQL` on the given DSN if not already present.

        Args:
            dsn: Target database connection URL.
        """
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
        finally:
            await conn.close()

    async def _ensure_schema(self, conn: asyncpg.Connection) -> None:
        """Execute schema DDL on an open connection.

        Deduplicates legacy multi-row host_results before creating the
        unique ``(session_id, host_id, framework_id)`` index.

        Args:
            conn: asyncpg connection with execute privileges.
        """
        await conn.execute(_SCHEMA_SQL)
        # Older builds inserted a new host_results row on every finalize.
        # Keep the newest id per (session, host, framework); CASCADE drops
        # orphaned requirement_results on the deleted rows.
        await conn.execute(
            """
            DELETE FROM host_results a
            USING host_results b
            WHERE a.session_id = b.session_id
              AND a.host_id = b.host_id
              AND a.framework_id = b.framework_id
              AND a.id < b.id
            """
        )
        await conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS host_results_session_host_fw_uidx
                ON host_results (session_id, host_id, framework_id)
            """
        )
        # CORE-003: add identity columns without inventing placeholder values.
        for stmt in (
            "ALTER TABLE requirement_results ADD COLUMN IF NOT EXISTS result_id UUID",
            "ALTER TABLE requirement_results ADD COLUMN IF NOT EXISTS client_id text",
            "ALTER TABLE requirement_results ADD COLUMN IF NOT EXISTS audit_run_id text",
            "ALTER TABLE requirement_results ADD COLUMN IF NOT EXISTS asset_id text",
            "ALTER TABLE requirement_results ADD COLUMN IF NOT EXISTS framework_id text",
            "ALTER TABLE requirement_results ADD COLUMN IF NOT EXISTS framework_version text",
            "ALTER TABLE hosts ADD COLUMN IF NOT EXISTS asset_id text",
            """
            CREATE UNIQUE INDEX IF NOT EXISTS requirement_results_result_id_uidx
                ON requirement_results (result_id)
                WHERE result_id IS NOT NULL
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS requirement_results_logical_key_uidx
                ON requirement_results (
                    client_id, audit_run_id, asset_id,
                    framework_id, framework_version, req_id
                )
                WHERE client_id IS NOT NULL
                  AND audit_run_id IS NOT NULL
                  AND asset_id IS NOT NULL
                  AND framework_id IS NOT NULL
                  AND framework_version IS NOT NULL
                  AND req_id IS NOT NULL
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS hosts_asset_id_uidx
                ON hosts (asset_id)
                WHERE asset_id IS NOT NULL
            """,
        ):
            await conn.execute(stmt)

    async def _ensure_playbook_schema(self, conn: asyncpg.Connection) -> None:
        """Create global ``playbook_memory`` table on the shared warehouse DB."""
        await conn.execute(_PLAYBOOK_SCHEMA_SQL)

    async def load_learned_playbooks(self) -> dict[str, dict[str, Any]]:
        """Load learned playbook entries from the shared results Postgres.

        Returns:
            Mapping ``framework_id → { entry_key → payload dict }``.
            Empty when disabled or on error.
        """
        if not self.enabled:
            return {}
        base = (self.settings.results_database_url or "").strip()
        if not base:
            return {}
        try:
            conn = await asyncpg.connect(base)
            try:
                await self._ensure_playbook_schema(conn)
                rows = await conn.fetch(
                    """
                    SELECT framework_id, entry_key, payload, source, updated_at
                    FROM playbook_memory
                    WHERE source = 'learned'
                    """
                )
            finally:
                await conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load playbook memory from Postgres: %s", exc)
            return {}
        out: dict[str, dict[str, Any]] = {}
        for row in rows:
            fw = str(row["framework_id"] or "")
            key = str(row["entry_key"] or "")
            if not fw or not key:
                continue
            payload = row["payload"]
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    continue
            if not isinstance(payload, dict):
                continue
            value = {
                **payload,
                "source": str(row["source"] or "learned"),
            }
            if row["updated_at"] is not None and "updated_at" not in value:
                value["updated_at"] = row["updated_at"].isoformat()
            out.setdefault(fw, {})[key] = value
        return out

    async def save_learned_playbooks(
        self, frameworks: Mapping[str, Mapping[str, Any]]
    ) -> int:
        """Replace learned playbook rows in Postgres with ``frameworks``.

        Deletes previous ``source='learned'`` rows, then upserts the provided
        entries. Seed YAML stays on disk and is never written here.

        Args:
            frameworks: ``framework_id → { entry_key → payload }``.

        Returns:
            Number of rows upserted, or ``0`` when disabled / on failure.
        """
        if not self.enabled:
            return 0
        base = (self.settings.results_database_url or "").strip()
        if not base:
            return 0
        try:
            conn = await asyncpg.connect(base)
            try:
                await self._ensure_playbook_schema(conn)
                async with conn.transaction():
                    await conn.execute(
                        "DELETE FROM playbook_memory WHERE source = 'learned'"
                    )
                    count = 0
                    for framework_id, entries in frameworks.items():
                        if not isinstance(entries, Mapping):
                            continue
                        fw = str(framework_id or "").strip()
                        if not fw:
                            continue
                        for entry_key, payload in entries.items():
                            key = str(entry_key or "").strip()
                            if not key or not isinstance(payload, dict):
                                continue
                            body = {**payload, "source": "learned"}
                            await conn.execute(
                                """
                                INSERT INTO playbook_memory (
                                    framework_id, entry_key, payload, source, updated_at
                                ) VALUES ($1, $2, $3::jsonb, 'learned', now())
                                ON CONFLICT (framework_id, entry_key) DO UPDATE SET
                                    payload = EXCLUDED.payload,
                                    source = 'learned',
                                    updated_at = now()
                                """,
                                fw,
                                key,
                                json.dumps(body, ensure_ascii=False),
                            )
                            count += 1
                    return count
            finally:
                await conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not save playbook memory to Postgres: %s", exc)
            return 0


_STORE: ResultsStore | None = None


def get_results_store(settings: Settings | None = None) -> ResultsStore | None:
    """Return a process-wide :class:`ResultsStore` when enabled, else ``None``.

    Caches a singleton per settings instance.

    Args:
        settings: Optional settings override.

    Returns:
        Enabled store instance, or ``None`` when results DB is disabled.
    """
    global _STORE
    settings = settings or get_settings()
    store = _STORE
    if store is None or store.settings is not settings:
        store = ResultsStore(settings)
        _STORE = store
    return store if store.enabled else None


async def start_session_safe(settings: Settings, **kwargs: Any) -> AuditSessionInfo | None:
    """Best-effort session allocation; returns None when disabled or on error.

    Args:
        settings: Auditor settings.
        **kwargs: Forwarded to :meth:`ResultsStore.start_session`.

    Returns:
        New :class:`AuditSessionInfo`, or ``None`` on failure/disabled.
    """
    store = get_results_store(settings)
    if store is None:
        return None
    try:
        return await store.start_session(**kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Results session start failed: %s", exc)
        return None




async def record_results_safe(
    settings: Settings,
    **kwargs: Any,
) -> None:
    """Best-effort warehouse write; log errors without failing the audit.

    Args:
        settings: Auditor settings.
        **kwargs: Forwarded to :meth:`ResultsStore.record_host_framework_audit`.
    """
    store = get_results_store(settings)
    if store is None:
        return
    try:
        await store.record_host_framework_audit(**kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Results DB write failed: %s", exc)


async def record_requirement_result_safe(
    settings: Settings,
    **kwargs: Any,
) -> None:
    """Best-effort live per-REQ warehouse upsert during assess.

    Args:
        settings: Auditor settings.
        **kwargs: Forwarded to :meth:`ResultsStore.upsert_requirement_result`.
    """
    store = get_results_store(settings)
    if store is None:
        return
    try:
        await store.upsert_requirement_result(**kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Results DB live REQ write failed: %s", exc)


async def snapshot_checklist_safe(settings: Settings, **kwargs: Any) -> None:
    """Best-effort checklist snapshot before assess (for N/M ready status)."""
    store = get_results_store(settings)
    if store is None:
        return
    try:
        await store.snapshot_framework_checklist(**kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Results DB checklist snapshot failed: %s", exc)


def format_sessions_markdown(sessions: Sequence[AuditSessionInfo]) -> str:
    """Operator-facing table of sessions (for chat list / continue help)."""
    if not sessions:
        return (
            "No audit sessions found in the results warehouse.\n\n"
            "Start a new audit (with `RESULTS_DB_ENABLED=true`) to create session #1."
        )
    lines = [
        "## Audit sessions (results warehouse)",
        "",
        "| Session | Client | Status | Framework | Pending | Thread |",
        "|---------|--------|--------|-----------|---------|--------|",
    ]
    for s in sessions:
        pending = ", ".join(s.pending_ids[:5])
        if len(s.pending_ids) > 5:
            pending += "…"
        thread = s.continue_thread_id or "—"
        lines.append(
            f"| **#{s.session_number}** | {s.client_name or s.client_slug} | "
            f"`{s.status}` | `{s.framework_id or '—'}` | {pending or '—'} | "
            f"`{thread}` |"
        )
    interrupted = [s for s in sessions if s.status == "interrupted"]
    if interrupted:
        lines.append("")
        lines.append("To resume a session, reply:")
        lines.append("")
        for s in interrupted[:10]:
            if s.continue_thread_id:
                lines.append(
                    f"- Client **{s.client_name or s.client_slug}** session "
                    f"**#{s.session_number}**: "
                    f"`[AUDIT_CONTINUE:{s.continue_thread_id}]`"
                )
            else:
                lines.append(
                    f"- Client **{s.client_name or s.client_slug}** session "
                    f"**#{s.session_number}**: say "
                    f"`continue session {s.session_number} for "
                    f"{s.client_name or s.client_slug}`"
                )
    return "\n".join(lines)


def discover_evidence_client_names(evidence_dir: Path | str) -> list[str]:
    """Return artifact folder names that look like client runs (have meta.json).

    Args:
        evidence_dir: Root evidence/artifacts directory.

    Returns:
        Sorted list of run folder names with ``meta.json`` present.
    """
    root = Path(evidence_dir)
    if not root.is_dir():
        return []
    names: list[str] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        if (child / "meta.json").is_file():
            names.append(child.name)
    return names


async def list_sessions_report(
    settings: Settings,
    *,
    client_name: str | None = None,
    status: str | None = None,
    interrupted_only: bool = False,
) -> str:
    """Build a markdown report of warehouse sessions for chat."""
    store = get_results_store(settings)
    if store is None:
        return (
            "Results warehouse is disabled. Set `RESULTS_DB_ENABLED=true` and "
            "`RESULTS_DATABASE_URL` to track numbered audit sessions in PostgreSQL."
        )
    want_status = "interrupted" if interrupted_only else status
    sessions: list[AuditSessionInfo] = []
    if client_name:
        sessions = await store.list_sessions(
            client_name=client_name, status=want_status, limit=50
        )
    else:
        clients = discover_evidence_client_names(settings.evidence_dir)
        if want_status == "interrupted":
            sessions = await store.list_interrupted_across_clients(clients)
        else:
            for name in clients:
                sessions.extend(
                    await store.list_sessions(
                        client_name=name, status=want_status, limit=10
                    )
                )
            sessions.sort(
                key=lambda s: s.started_at
                or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
    return format_sessions_markdown(sessions)


def _disk_meta_for_run(evidence_dir: Path | str, run_id: str) -> dict[str, Any]:
    """Load ``meta.json`` for an evidence run when present."""
    meta_path = Path(evidence_dir) / run_id / "meta.json"
    if not meta_path.is_file():
        return {}
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def resolve_session_evidence(
    settings: Settings,
    info: AuditSessionInfo,
) -> tuple[str, str]:
    """Map a warehouse session to the real on-disk ``(thread_id, run_id)``.

    After intake the evidence folder is renamed to the client slug, but the
    warehouse may still store the temporary run id and a short base thread.
    Prefer the client-slug folder / ``meta.json`` thread when available.
    """
    evidence_dir = Path(settings.evidence_dir)
    candidates: list[str] = []
    for cand in (
        info.client_slug,
        make_client_slug(info.client_name),
        info.evidence_run_id,
    ):
        c = (cand or "").strip()
        if c and c not in candidates:
            candidates.append(c)

    chosen_run = ""
    meta: dict[str, Any] = {}
    for cand in candidates:
        path = evidence_dir / cand
        if not path.is_dir():
            continue
        # Prefer folders that still have checklist evidence / meta.
        m = _disk_meta_for_run(evidence_dir, cand)
        if m or any(path.iterdir()):
            chosen_run = cand
            meta = m
            if m:
                break
    if not chosen_run:
        chosen_run = (info.evidence_run_id or info.client_slug or "").strip()
        meta = _disk_meta_for_run(evidence_dir, chosen_run) if chosen_run else {}

    tid = str(
        meta.get("continue_thread_id")
        or meta.get("thread_id")
        or info.continue_thread_id
        or ""
    ).strip()
    # Prefer host/framework-scoped thread from session.json when warehouse
    # only has the short base id (``audit-<hex>``).
    if chosen_run and (":" not in tid or tid.count(":") < 2):
        from auditor.session_store import load_all_multi_sessions

        sessions = load_all_multi_sessions(evidence_dir, chosen_run)
        if sessions:
            # Newest / only active thread key.
            tid = next(iter(sessions.keys()))
    return tid, chosen_run


def parse_continue_session_request(
    user_text: str,
) -> tuple[int | None, str | None]:
    """Extract ``(session_number, client_hint)`` from a continue phrase."""
    session_num: int | None = None
    m = re.search(
        r"(?:continue|resume|продолж\w*)\s+(?:audit\s+)?session\s+#?(\d+)"
        r"|(?:сесси[яию]\w*)\s+#?(\d+)",
        user_text or "",
        re.I,
    )
    if m:
        session_num = int(m.group(1) or m.group(2))
    client_hint = None
    cm = re.search(
        r"\b(?:for|для)\s+([A-Za-z0-9][A-Za-z0-9 _.-]{1,80})",
        user_text or "",
        re.I,
    )
    if cm:
        client_hint = cm.group(1).strip().rstrip("?.!,")
    return session_num, client_hint


def parse_list_results_request(
    user_text: str,
) -> tuple[str | None, int | None]:
    """Extract ``(client_name, session_number)`` from a list-results phrase.

    Supports::

        List results for AlphaCo session 2
        list-results AlphaCo 2
        Show warehouse results for AlphaCo #2
        Результаты для AlphaCo сессия 2

    Session number may be omitted (caller uses latest session for the client).
    """
    text = (user_text or "").strip()
    if not text:
        return None, None

    # ``list-results Client 2`` / ``list results Client 2``
    m = re.search(
        r"\blist[- ]?results\s+([A-Za-z0-9][A-Za-z0-9._-]{1,63})\s+#?(\d+)\b",
        text,
        re.I,
    )
    if m:
        return m.group(1), int(m.group(2))

    # ``… for Client session 2`` / ``… для Client сессия 2``
    m = re.search(
        r"\b(?:for|для)\s+([A-Za-z0-9][A-Za-z0-9 _.-]{1,80}?)\s+"
        r"(?:session|сесси[яию]|#)\s*#?(\d+)\b",
        text,
        re.I,
    )
    if m:
        return m.group(1).strip().rstrip("?.!,"), int(m.group(2))

    client_hint = None
    cm = re.search(
        r"\b(?:for|для)\s+([A-Za-z0-9][A-Za-z0-9 _.-]{1,80})",
        text,
        re.I,
    )
    if cm:
        client_hint = cm.group(1).strip().rstrip("?.!,")
    session_num = None
    sm = re.search(
        r"(?:session|сесси[яию]|#)\s*#?(\d+)\b",
        text,
        re.I,
    )
    if sm:
        session_num = int(sm.group(1))
    return client_hint, session_num


def parse_list_status_request(
    user_text: str,
) -> tuple[str | None, int | None]:
    """Extract ``(client_name, session_number)`` from a list-status phrase.

    Supports::

        List status for AlphaCo session 2
        list-status AlphaCo 2
        /list-status
    """
    text = (user_text or "").strip()
    if not text:
        return None, None

    m = re.search(
        r"\blist[- ]?status\s+([A-Za-z0-9][A-Za-z0-9._-]{1,63})\s+#?(\d+)\b",
        text,
        re.I,
    )
    if m:
        return m.group(1), int(m.group(2))

    m = re.search(
        r"\b(?:for|для)\s+([A-Za-z0-9][A-Za-z0-9 _.-]{1,80}?)\s+"
        r"(?:session|сесси[яию]|#)\s*#?(\d+)\b",
        text,
        re.I,
    )
    if m:
        return m.group(1).strip().rstrip("?.!,"), int(m.group(2))

    client_hint = None
    cm = re.search(
        r"\b(?:for|для)\s+([A-Za-z0-9][A-Za-z0-9 _.-]{1,80})",
        text,
        re.I,
    )
    if cm:
        client_hint = cm.group(1).strip().rstrip("?.!,")
    session_num = None
    sm = re.search(
        r"(?:session|сесси[яию]|#)\s*#?(\d+)\b",
        text,
        re.I,
    )
    if sm:
        session_num = int(sm.group(1))
    return client_hint, session_num


def parse_list_host_request(
    user_text: str,
) -> tuple[str | None, str | None, str | None]:
    """Extract ``(hostname, framework_id, client_hint)`` from a list-host phrase.

    Supports::

        list-host pg-db it_audit
        List host 10.200.29.79 framework ubuntu_cis_24_l2
        list-host 10.0.0.1 it_audit for AlphaCo
    """
    text = (user_text or "").strip()
    if not text:
        return None, None, None

    client_hint = None
    cm = re.search(
        r"\b(?:for|для)\s+([A-Za-z0-9][A-Za-z0-9 _.-]{1,80})",
        text,
        re.I,
    )
    if cm:
        client_hint = cm.group(1).strip().rstrip("?.!,")

    m = re.search(
        r"\blist[- ]?host\s+(\S+)\s+(?:framework\s+)?([A-Za-z0-9][A-Za-z0-9._-]{1,80})",
        text,
        re.I,
    )
    if m:
        return m.group(1).strip(), m.group(2).strip(), client_hint

    m = re.search(
        r"\b(?:host|хост)\s+(\S+)\s+(?:framework|фреймворк)\s+"
        r"([A-Za-z0-9][A-Za-z0-9._-]{1,80})",
        text,
        re.I,
    )
    if m:
        return m.group(1).strip(), m.group(2).strip(), client_hint

    return None, None, client_hint


def _truncate_cell(text: str, limit: int = 140) -> str:
    raw = re.sub(r"\s+", " ", (text or "").strip())
    if len(raw) <= limit:
        return raw
    return raw[: limit - 1] + "…"


def format_session_results_markdown(
    session: AuditSessionInfo,
    host_rows: Sequence[Mapping[str, Any]],
    req_rows: Sequence[Mapping[str, Any]],
) -> str:
    """Operator-facing warehouse results for one session (chat)."""
    lines = [
        f"## Audit results — **{session.client_name or session.client_slug}** "
        f"session **#{session.session_number}**",
        "",
        f"- **Status:** `{session.status}`",
        f"- **Framework:** `{session.framework_id or '—'}`",
        f"- **Evidence:** `{session.evidence_run_id or '—'}`",
    ]
    if session.started_at:
        lines.append(f"- **Started:** {session.started_at.isoformat()}")
    if session.finished_at:
        lines.append(f"- **Finished:** {session.finished_at.isoformat()}")
    lines.append("")

    if host_rows:
        lines.extend(
            [
                "### Host / framework summary",
                "",
                "| Host | Framework | Compliance % | Pass | Fail | Partial | Error | Skip |",
                "|------|-----------|-------------:|-----:|-----:|--------:|------:|-----:|",
            ]
        )
        for h in host_rows:
            lines.append(
                f"| `{h.get('host_label') or '—'}` | `{h.get('framework_id') or '—'}` | "
                f"{float(h.get('compliance_pct') or 0):.1f} | "
                f"{int(h.get('pass_count') or 0)} | {int(h.get('fail_count') or 0)} | "
                f"{int(h.get('partial_count') or 0)} | {int(h.get('error_count') or 0)} | "
                f"{int(h.get('skipped_count') or 0)} |"
            )
        lines.append("")

    if not req_rows:
        lines.append("_No requirement cells stored for this session yet._")
        lines.append("")
        lines.append(
            "Cells are written on **finalize** / **Update the report**. "
            "Interrupted sessions may have empty results until the audit finishes."
        )
        return "\n".join(lines)

    lines.extend(
        [
            "### Requirement cells",
            "",
            "| REQ | Title | Status | Severity | Framework | Host | Observation |",
            "|-----|-------|--------|----------|-----------|------|-------------|",
        ]
    )
    for r in req_rows:
        title = _truncate_cell(str(r.get("title") or ""), 48)
        obs = _truncate_cell(str(r.get("observation") or ""), 100)
        # Escape pipes in markdown cells
        title = title.replace("|", "/")
        obs = obs.replace("|", "/")
        lines.append(
            f"| `{r.get('req_id') or '—'}` | {title or '—'} | "
            f"`{r.get('status') or '—'}` | {r.get('severity') or '—'} | "
            f"`{r.get('framework_id') or '—'}` | `{r.get('host_label') or '—'}` | "
            f"{obs or '—'} |"
        )
    lines.append("")
    lines.append(
        "Next: `/update-report` for the Markdown/ZIP, or `/gather-req` / "
        "`/refill-req` to refine a REQ on this client's evidence."
    )
    return "\n".join(lines)


async def list_results_report(
    settings: Settings,
    *,
    client_name: str | None,
    session_number: int | None = None,
) -> str:
    """Build a markdown report of warehouse REQ cells for chat."""
    store = get_results_store(settings)
    if store is None:
        return (
            "Results warehouse is disabled. Set `RESULTS_DB_ENABLED=true` and "
            "`RESULTS_DATABASE_URL` to store filled REQ cells in PostgreSQL."
        )
    if not client_name:
        return (
            "Specify a client, e.g. `List results for AlphaCo session 2` "
            "or slash `/list-results`."
        )

    info: AuditSessionInfo | None = None
    if session_number is not None:
        info = await store.get_session(
            client_name=client_name, session_number=session_number
        )
        if info is None:
            return (
                f"No warehouse session **#{session_number}** for "
                f"**{client_name}**.\n\n"
                f"Try `List audit sessions for {client_name}`."
            )
    else:
        info = await store.get_latest_session(client_name=client_name)
        if info is None:
            return (
                f"No warehouse sessions for **{client_name}**.\n\n"
                "Start an audit (with `RESULTS_DB_ENABLED=true`) first."
            )

    sess, hosts, reqs = await store.list_session_requirement_results(
        client_name=client_name,
        session_number=info.session_number,
    )
    if sess is None:
        return (
            f"Could not load session **#{info.session_number}** for "
            f"**{client_name}**."
        )
    return format_session_results_markdown(sess, hosts, reqs)


def format_session_status_markdown(
    session: AuditSessionInfo,
    host_rows: Sequence[Mapping[str, Any]],
) -> str:
    """Operator-facing host progress table for ``/list-status``."""
    lines = [
        f"## Host status — **{session.client_name or session.client_slug}** "
        f"session **#{session.session_number}**",
        "",
        f"- **Session status:** `{session.status}`",
        f"- **Evidence:** `{session.evidence_run_id or '—'}`",
        "",
    ]
    if not host_rows:
        lines.append("_No host/framework rows stored for this session yet._")
        lines.append("")
        lines.append(
            "Rows appear when assess starts (checklist snapshot) and grow as "
            "each REQ is filled live."
        )
        return "\n".join(lines)

    lines.extend(
        [
            "| Hostname | IP | Framework | Status |",
            "|----------|----|-----------|--------|",
        ]
    )
    for h in host_rows:
        lines.append(
            f"| `{h.get('hostname') or '—'}` | `{h.get('ip') or '—'}` | "
            f"`{h.get('framework_id') or '—'}` | "
            f"{h.get('ready_label') or '—'} |"
        )
    lines.append("")
    lines.append(
        "Next: `/list-results` for REQ cells, or `/list-host <hostname> "
        "<framework>` for one host."
    )
    return "\n".join(lines)


def format_host_framework_results_markdown(
    meta: Mapping[str, Any],
    req_rows: Sequence[Mapping[str, Any]],
) -> str:
    """Operator-facing REQ table for ``/list-host``."""
    lines = [
        f"## Host results — **{meta.get('hostname') or meta.get('host_key') or '—'}** "
        f"/ `{meta.get('framework_id') or '—'}`",
        "",
        f"- **Client:** {meta.get('client_name') or meta.get('client_slug') or '—'}",
        f"- **Session:** **#{meta.get('session_number') or '—'}** "
        f"(`{meta.get('session_status') or '—'}`)",
        f"- **IP / SSH:** `{meta.get('ip') or '—'}`",
        f"- **Compliance:** {float(meta.get('compliance_pct') or 0):.1f}% "
        f"(pass {int(meta.get('pass_count') or 0)} / "
        f"fail {int(meta.get('fail_count') or 0)} / "
        f"partial {int(meta.get('partial_count') or 0)} / "
        f"error {int(meta.get('error_count') or 0)} / "
        f"skip {int(meta.get('skipped_count') or 0)})",
        "",
    ]
    if not req_rows:
        lines.append("_No requirement cells stored for this host/framework yet._")
        return "\n".join(lines)

    lines.extend(
        [
            "| REQ | Title | Status | Severity | Observation |",
            "|-----|-------|--------|----------|-------------|",
        ]
    )
    for r in req_rows:
        title = _truncate_cell(str(r.get("title") or ""), 48).replace("|", "/")
        obs = _truncate_cell(str(r.get("observation") or ""), 100).replace("|", "/")
        lines.append(
            f"| `{r.get('req_id') or '—'}` | {title or '—'} | "
            f"`{r.get('status') or '—'}` | {r.get('severity') or '—'} | "
            f"{obs or '—'} |"
        )
    lines.append("")
    return "\n".join(lines)


async def list_status_report(
    settings: Settings,
    *,
    client_name: str | None,
    session_number: int | None = None,
) -> str:
    """Build a markdown host-status table for chat (``/list-status``)."""
    store = get_results_store(settings)
    if store is None:
        return (
            "Results warehouse is disabled. Set `RESULTS_DB_ENABLED=true` and "
            "`RESULTS_DATABASE_URL` to track host progress in PostgreSQL."
        )
    if not client_name:
        return (
            "Specify a client, e.g. `List status for AlphaCo session 2` "
            "or slash `/list-status`."
        )

    info: AuditSessionInfo | None = None
    if session_number is not None:
        info = await store.get_session(
            client_name=client_name, session_number=session_number
        )
        if info is None:
            return (
                f"No warehouse session **#{session_number}** for "
                f"**{client_name}**.\n\n"
                f"Try `List audit sessions for {client_name}`."
            )
    else:
        info = await store.get_latest_session(client_name=client_name)
        if info is None:
            return (
                f"No warehouse sessions for **{client_name}**.\n\n"
                "Start an audit (with `RESULTS_DB_ENABLED=true`) first."
            )

    sess, rows = await store.list_session_host_status(
        client_name=client_name,
        session_number=info.session_number,
    )
    if sess is None:
        return (
            f"Could not load session **#{info.session_number}** for "
            f"**{client_name}**."
        )
    return format_session_status_markdown(sess, rows)


async def list_host_report(
    settings: Settings,
    *,
    hostname: str | None,
    framework_id: str | None,
    client_name: str | None = None,
) -> str:
    """Build a markdown REQ dump for one host+framework (``/list-host``)."""
    store = get_results_store(settings)
    if store is None:
        return (
            "Results warehouse is disabled. Set `RESULTS_DB_ENABLED=true` and "
            "`RESULTS_DATABASE_URL` to store host assessment results."
        )
    if not hostname or not framework_id:
        return (
            "Specify hostname and framework, e.g. "
            "`list-host 10.200.29.79 it_audit` or slash `/list-host`."
        )

    clients = (
        [client_name]
        if client_name
        else discover_evidence_client_names(settings.evidence_dir)
    )
    meta, reqs = await store.list_host_framework_results(
        hostname=hostname,
        framework_id=framework_id,
        client_names=[c for c in clients if c],
        client_name=client_name,
    )
    if meta is None:
        scope = f" for **{client_name}**" if client_name else ""
        return (
            f"No warehouse results for host `{hostname}` / framework "
            f"`{framework_id}`{scope}.\n\n"
            "Try `/list-status` or `/list-sessions` to find a session."
        )
    return format_host_framework_results_markdown(meta, reqs)


async def resolve_continue_target(
    settings: Settings,
    user_text: str = "",
) -> tuple[str, str, AuditSessionInfo | None] | None:
    """Resolve ``(thread_id, run_id, session)`` for a continue request.

    Prefers an explicit ``continue session N for Client`` from the warehouse,
    then the newest interrupted warehouse session among known clients, then
    falls back to disk ``find_interrupted_run``.

    Always remaps warehouse ``evidence_run_id`` / short thread ids to the
    current on-disk client folder and host-scoped LangGraph thread when possible.
    """
    from auditor.session_store import find_interrupted_run

    store = get_results_store(settings)
    session_num, client_hint = parse_continue_session_request(user_text)

    if store is not None and session_num is not None and client_hint:
        info = await store.get_session(
            client_name=client_hint, session_number=session_num
        )
        if info is not None:
            tid, run_id = resolve_session_evidence(settings, info)
            if tid and run_id:
                # Keep warehouse pointers fresh for the next continue.
                try:
                    await store.update_session_status(
                        client_name=client_hint,
                        session_number=session_num,
                        status=info.status or "interrupted",
                        continue_thread_id=tid,
                        evidence_run_id=run_id,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Could not refresh session resume pointers: %s", exc)
                return tid, run_id, info

    if store is not None:
        clients = (
            [client_hint]
            if client_hint
            else discover_evidence_client_names(settings.evidence_dir)
        )
        interrupted = await store.list_interrupted_across_clients(
            [c for c in clients if c]
        )
        if session_num is not None:
            interrupted = [
                s for s in interrupted if s.session_number == session_num
            ]
        if interrupted:
            info = interrupted[0]
            tid, run_id = resolve_session_evidence(settings, info)
            if tid and run_id:
                return tid, run_id, info

    found = find_interrupted_run(settings.evidence_dir)
    if not found:
        return None
    run_id, meta = found
    tid = str(meta.get("continue_thread_id") or meta.get("thread_id") or "")
    if not tid:
        return None
    return tid, run_id, None


async def sync_session_status_from_run_meta(
    settings: Settings,
    *,
    run_id: str,
    status: str,
    thread_id: str = "",
    pending_ids: Sequence[str] | None = None,
    framework_id: str = "",
) -> None:
    """Update warehouse session using ``results_session_number`` from disk meta.

    Reads ``meta.json`` from the evidence run and calls
    :meth:`ResultsStore.update_session_status` when a session number is stored.

    Args:
        settings: Auditor settings.
        run_id: Evidence run folder name.
        status: New session status.
        thread_id: Continue thread id for interrupted runs.
        pending_ids: Remaining requirement ids.
        framework_id: Active framework id.
    """
    store = get_results_store(settings)
    if store is None:
        return
    try:
        from auditor.evidence_store import EvidenceStore

        ev = EvidenceStore.open_existing(settings.evidence_dir, run_id)
        meta = ev.read_run_meta()
        session_number = meta.get("results_session_number")
        if session_number is None:
            return
        client = str(meta.get("client_name") or run_id)
        await store.update_session_status(
            client_name=client,
            session_number=int(session_number),
            status=status,
            continue_thread_id=thread_id or None,
            pending_ids=pending_ids,
            framework_id=framework_id or None,
            evidence_run_id=run_id or None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Results session sync failed: %s", exc)

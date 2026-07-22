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

Pipeline role:
    :func:`start_session_safe` allocates session numbers at intake; finalize and
    :func:`~auditor.followup.run_update_report` call :func:`record_results_safe`
    to upsert findings. ``continue`` resumes the same session without a new number.

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
from auditor.intake import client_slug as make_client_slug
from auditor.state import Finding

logger = logging.getLogger(__name__)

_SAFE_DB = re.compile(r"[^a-z0-9_]+")

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
    UNIQUE (host_result_id, req_id)
);

CREATE INDEX IF NOT EXISTS requirement_results_session_idx
    ON requirement_results (session_id, req_id);
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

                host_pk = await conn.fetchval(
                    """
                    INSERT INTO hosts (host_key, ssh_host, hostname, last_seen_at)
                    VALUES ($1, $2, $3, now())
                    ON CONFLICT (host_key) DO UPDATE SET
                        last_seen_at = now(),
                        ssh_host = COALESCE(EXCLUDED.ssh_host, hosts.ssh_host),
                        hostname = COALESCE(EXCLUDED.hostname, hosts.hostname)
                    RETURNING id
                    """,
                    host_key,
                    host_key if host_key != "_default" else None,
                    host_key if host_key != "_default" else None,
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
                hr_pk = await conn.fetchval(
                    """
                    INSERT INTO host_results (
                        session_id, session_number, host_id, framework_id,
                        finished_at, source,
                        pass_count, fail_count, partial_count, error_count,
                        skipped_count, assessed, compliance_pct,
                        evidence_relpath, report_relpath
                    ) VALUES (
                        $1,$2,$3,$4,now(),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
                    ) RETURNING id
                    """,
                    session_pk,
                    sess_num,
                    host_pk,
                    fw,
                    source,
                    int(metrics.get("pass", 0)),
                    int(metrics.get("fail", 0)),
                    int(metrics.get("partial", 0)),
                    int(metrics.get("error", 0)),
                    int(metrics.get("skipped", 0)),
                    int(metrics.get("assessed", 0)),
                    float(metrics.get("compliance_pct", 0.0)),
                    evidence_relpath or run_id,
                    report_rel,
                )
                req_map = requirements or {}
                for _req_id, finding in findings.items():
                    req = req_map.get(finding.requirement_id) if req_map else None
                    await conn.execute(
                        """
                        INSERT INTO requirement_results (
                            host_result_id, session_id, session_number,
                            req_id, title, category, severity,
                            status, pass_criteria, how_to_verify,
                            observation, recommendation, notes
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
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
                            session_number = EXCLUDED.session_number
                        """,
                        hr_pk,
                        session_pk,
                        sess_num,
                        finding.requirement_id,
                        finding.title or (req.title if req else ""),
                        finding.category or (req.category if req else ""),
                        finding.severity or (req.severity if req else ""),
                        finding.status,
                        finding.pass_criteria or (req.pass_criteria if req else ""),
                        (req.how_to_verify if req else ""),
                        finding.evidence or "",
                        finding.remediation or "",
                        finding.notes or "",
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

        Args:
            conn: asyncpg connection with execute privileges.
        """
        await conn.execute(_SCHEMA_SQL)


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

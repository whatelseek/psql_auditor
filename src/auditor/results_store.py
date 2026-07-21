"""PostgreSQL warehouse for audit results (per-client DB, evidence stays on disk).

Layout (when ``RESULTS_DB_PER_CLIENT=true``)::

    results_<client_slug>
      hosts
      audit_runs
      host_results
      framework_requirements   -- checklist snapshot for the run/framework
      requirement_results      -- full filled cells (status/obs/rec)

Tool stdout remains under ``artifacts/<client>/<host>/<framework>/REQ-*/``.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlparse, urlunparse

import asyncpg

from auditor.benchmark_store import findings_to_benchmark_metrics
from auditor.checklist import Requirement
from auditor.config import Settings, get_settings
from auditor.intake import client_slug as make_client_slug
from auditor.state import Finding

logger = logging.getLogger(__name__)

_SAFE_DB = re.compile(r"[^a-z0-9_]+")

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS hosts (
    id              bigserial PRIMARY KEY,
    host_key        text NOT NULL,
    ssh_host        text,
    hostname        text,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (host_key)
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id              bigserial PRIMARY KEY,
    evidence_run_id text NOT NULL,
    client_name     text NOT NULL DEFAULT '',
    client_slug     text NOT NULL DEFAULT '',
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    status          text NOT NULL DEFAULT 'completed',
    report_language text,
    evidence_path   text NOT NULL DEFAULT '',
    UNIQUE (evidence_run_id)
);

CREATE TABLE IF NOT EXISTS host_results (
    id              bigserial PRIMARY KEY,
    run_id          bigint NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS host_results_host_finished_idx
    ON host_results (host_id, finished_at DESC);
CREATE INDEX IF NOT EXISTS host_results_framework_finished_idx
    ON host_results (framework_id, finished_at DESC);

CREATE TABLE IF NOT EXISTS framework_requirements (
    id              bigserial PRIMARY KEY,
    run_id          bigint NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    framework_id    text NOT NULL,
    req_id          text NOT NULL,
    title           text NOT NULL DEFAULT '',
    category        text NOT NULL DEFAULT '',
    severity        text NOT NULL DEFAULT '',
    how_to_verify   text NOT NULL DEFAULT '',
    pass_criteria   text NOT NULL DEFAULT '',
    UNIQUE (run_id, framework_id, req_id)
);

CREATE TABLE IF NOT EXISTS requirement_results (
    id              bigserial PRIMARY KEY,
    host_result_id  bigint NOT NULL REFERENCES host_results(id) ON DELETE CASCADE,
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
"""


def sanitize_db_name(prefix: str, client_slug: str) -> str:
    """Build a PostgreSQL-safe database name: ``{prefix}{slug}``."""
    pref = _SAFE_DB.sub("_", (prefix or "results_").lower()).strip("_") or "results"
    slug = _SAFE_DB.sub("_", (client_slug or "client").lower()).strip("_") or "client"
    name = f"{pref}_{slug}" if not pref.endswith("_") else f"{pref}{slug}"
    return name[:63]


def _swap_database(dsn: str, database: str) -> str:
    """Return ``dsn`` with the path/database component replaced."""
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
    """Connect to the server's maintenance DB (``postgres``) for CREATE DATABASE."""
    return _swap_database(dsn, "postgres")


class ResultsStore:
    """Write audit checklist + findings into a per-client results database."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        return bool(
            self.settings.results_db_enabled
            and (self.settings.results_database_url or "").strip()
        )

    def client_database_name(self, client_name: str) -> str:
        slug = make_client_slug(client_name) or "client"
        return sanitize_db_name(self.settings.results_db_name_prefix, slug)

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
    ) -> None:
        """Upsert run/host and insert timestamped results + full checklist cells."""
        if not self.enabled:
            return
        if not findings and not requirements:
            return
        client = (client_name or evidence_run_id or "client").strip()
        run_id = (evidence_run_id or "").strip() or make_client_slug(client)
        fw = (framework_id or "").strip() or "framework"
        # Bare framework id when evidence key is ``host/fw``.
        if "/" in fw:
            host_from_key, bare = fw.split("/", 1)
            fw = bare or fw
            if not evidence_host_id:
                evidence_host_id = host_from_key
        host_key = (evidence_host_id or "").strip() or "_default"
        slug = make_client_slug(client)

        dsn = await self._connect_dsn_for_client(slug)
        metrics = findings_to_benchmark_metrics(findings) if findings else {
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
                run_pk = await conn.fetchval(
                    """
                    INSERT INTO audit_runs (
                        evidence_run_id, client_name, client_slug,
                        finished_at, status, report_language, evidence_path
                    ) VALUES ($1, $2, $3, $4, 'completed', $5, $6)
                    ON CONFLICT (evidence_run_id) DO UPDATE SET
                        finished_at = EXCLUDED.finished_at,
                        status = EXCLUDED.status,
                        report_language = COALESCE(EXCLUDED.report_language, audit_runs.report_language),
                        evidence_path = COALESCE(NULLIF(EXCLUDED.evidence_path, ''), audit_runs.evidence_path),
                        client_name = EXCLUDED.client_name,
                        client_slug = EXCLUDED.client_slug
                    RETURNING id
                    """,
                    run_id,
                    client,
                    slug,
                    datetime.now(timezone.utc),
                    report_language,
                    evidence_relpath or run_id,
                )
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
                                run_id, framework_id, req_id, title, category,
                                severity, how_to_verify, pass_criteria
                            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                            ON CONFLICT (run_id, framework_id, req_id) DO UPDATE SET
                                title = EXCLUDED.title,
                                category = EXCLUDED.category,
                                severity = EXCLUDED.severity,
                                how_to_verify = EXCLUDED.how_to_verify,
                                pass_criteria = EXCLUDED.pass_criteria
                            """,
                            run_pk,
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
                        run_id, host_id, framework_id, finished_at, source,
                        pass_count, fail_count, partial_count, error_count,
                        skipped_count, assessed, compliance_pct,
                        evidence_relpath, report_relpath
                    ) VALUES (
                        $1,$2,$3,now(),$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
                    ) RETURNING id
                    """,
                    run_pk,
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
                for req_id, finding in findings.items():
                    req = req_map.get(req_id) if req_map else None
                    await conn.execute(
                        """
                        INSERT INTO requirement_results (
                            host_result_id, req_id, title, category, severity,
                            status, pass_criteria, how_to_verify,
                            observation, recommendation, notes
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                        ON CONFLICT (host_result_id, req_id) DO UPDATE SET
                            title = EXCLUDED.title,
                            category = EXCLUDED.category,
                            severity = EXCLUDED.severity,
                            status = EXCLUDED.status,
                            pass_criteria = EXCLUDED.pass_criteria,
                            how_to_verify = EXCLUDED.how_to_verify,
                            observation = EXCLUDED.observation,
                            recommendation = EXCLUDED.recommendation,
                            notes = EXCLUDED.notes
                        """,
                        hr_pk,
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
        finally:
            await conn.close()

    async def _connect_dsn_for_client(self, client_slug: str) -> str:
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
        maint = _maintenance_dsn(admin_dsn)
        conn = await asyncpg.connect(maint)
        try:
            exists = await conn.fetchval(
                "SELECT 1 FROM pg_database WHERE datname = $1", db_name
            )
            if not exists:
                # CREATE DATABASE cannot run inside a transaction block.
                await conn.execute(f'CREATE DATABASE "{db_name}"')
                logger.info("Created results database %s", db_name)
        finally:
            await conn.close()

    async def _ensure_schema_on_dsn(self, dsn: str) -> None:
        conn = await asyncpg.connect(dsn)
        try:
            await self._ensure_schema(conn)
        finally:
            await conn.close()

    async def _ensure_schema(self, conn: asyncpg.Connection) -> None:
        await conn.execute(_SCHEMA_SQL)


_STORE: ResultsStore | None = None


def get_results_store(settings: Settings | None = None) -> ResultsStore | None:
    """Return a process ResultsStore when enabled, else ``None``."""
    global _STORE
    settings = settings or get_settings()
    store = _STORE
    if store is None or store.settings is not settings:
        store = ResultsStore(settings)
        _STORE = store
    return store if store.enabled else None


async def record_results_safe(
    settings: Settings,
    **kwargs: Any,
) -> None:
    """Best-effort warehouse write; log errors without failing the audit."""
    store = get_results_store(settings)
    if store is None:
        return
    try:
        await store.record_host_framework_audit(**kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Results DB write failed: %s", exc)

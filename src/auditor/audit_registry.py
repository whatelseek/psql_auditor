"""Persistent AuditRun / AuditJob registry (outside LangGraph nodes).

Storage: SQLite under ``<evidence_dir>/.audit_registry.sqlite`` so identity
survives process restarts without depending on the results warehouse.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from auditor.domain.audit_models import (
    AuditJob,
    AuditJobStatus,
    AuditJobType,
    AuditRun,
    AuditRunStatus,
    InvalidStatusTransition,
    JobErrorInfo,
    can_complete_run,
    new_audit_run_id,
    new_job_id,
    resolve_terminal_run_status,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_runs (
    audit_run_id            TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL DEFAULT '',
    scope_json              TEXT NOT NULL DEFAULT '{}',
    status                  TEXT NOT NULL DEFAULT 'pending',
    created_at              TEXT NOT NULL,
    started_at              TEXT,
    finished_at             TEXT,
    evidence_run_id         TEXT NOT NULL DEFAULT '',
    results_session_number  INTEGER,
    base_thread_id          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_runs_client_created_idx
    ON audit_runs (client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_runs_status_idx
    ON audit_runs (status);

CREATE TABLE IF NOT EXISTS audit_jobs (
    job_id              TEXT PRIMARY KEY,
    audit_run_id        TEXT NOT NULL REFERENCES audit_runs(audit_run_id)
                            ON DELETE CASCADE,
    job_type            TEXT NOT NULL DEFAULT 'assess_framework',
    logical_task_id     TEXT NOT NULL,
    attempt             INTEGER NOT NULL DEFAULT 1,
    status              TEXT NOT NULL DEFAULT 'pending',
    mandatory           INTEGER NOT NULL DEFAULT 1,
    started_at          TEXT,
    finished_at         TEXT,
    error_json          TEXT,
    thread_id           TEXT NOT NULL DEFAULT '',
    framework_id        TEXT NOT NULL DEFAULT '',
    host_id             TEXT NOT NULL DEFAULT '',
    UNIQUE (audit_run_id, logical_task_id, attempt)
);

CREATE INDEX IF NOT EXISTS audit_jobs_run_idx
    ON audit_jobs (audit_run_id, logical_task_id, attempt);
CREATE INDEX IF NOT EXISTS audit_jobs_status_idx
    ON audit_jobs (status);
"""


class AuditRegistry:
    """CRUD + transition helpers for :class:`AuditRun` / :class:`AuditJob`."""

    def __init__(self, db_path: Path | str) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _ensure_schema(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
                conn.commit()

    # --- runs -----------------------------------------------------------------

    def create_run(
        self,
        *,
        client_id: str,
        scope: dict[str, Any] | None = None,
        evidence_run_id: str = "",
        base_thread_id: str = "",
        results_session_number: int | None = None,
        audit_run_id: str | None = None,
    ) -> AuditRun:
        """Create a new pending audit run (full restart → new id)."""
        from auditor.legacy_compat import require_client_id

        cid = require_client_id(client_id, context="AuditRegistry.create_run")
        run = AuditRun(
            audit_run_id=audit_run_id or new_audit_run_id(),
            client_id=cid,
            scope=dict(scope or {}),
            evidence_run_id=evidence_run_id,
            base_thread_id=base_thread_id,
            results_session_number=results_session_number,
        )
        with self._lock:
            with self._connect() as conn:
                self._insert_run(conn, run)
                conn.commit()
        return run

    def get_run(self, audit_run_id: str) -> AuditRun | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM audit_runs WHERE audit_run_id = ?",
                    (audit_run_id,),
                ).fetchone()
        return self._row_to_run(row) if row else None

    def get_run_by_evidence_id(self, evidence_run_id: str) -> AuditRun | None:
        """Lookup by evidence folder id.

        When multiple AuditRuns share the same evidence path (legacy), raises
        :class:`~auditor.legacy_compat.AmbiguousLegacyRunError` instead of
        silently returning the newest row (CORE-001).
        """
        if not evidence_run_id:
            return None
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM audit_runs WHERE evidence_run_id = ? ORDER BY created_at DESC",
                    (evidence_run_id,),
                ).fetchall()
        if not rows:
            return None
        if len(rows) > 1:
            from auditor.legacy_compat import AmbiguousLegacyRunError

            raise AmbiguousLegacyRunError(
                f"multiple AuditRuns for evidence_run_id={evidence_run_id!r}",
                candidates=[str(r["audit_run_id"]) for r in rows],
            )
        return self._row_to_run(rows[0])

    def save_run(self, run: AuditRun) -> None:
        from auditor.legacy_compat import ClientOwnershipError, require_client_id

        cid = require_client_id(run.client_id, context="AuditRegistry.save_run")
        existing = self.get_run(run.audit_run_id)
        if existing is not None:
            prev = (existing.client_id or "").strip()
            if prev and prev != cid:
                raise ClientOwnershipError(
                    f"cannot reassign audit_run_id {run.audit_run_id!r} from "
                    f"client_id={prev!r} to {cid!r}"
                )
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE audit_runs SET
                        client_id = ?,
                        scope_json = ?,
                        status = ?,
                        started_at = ?,
                        finished_at = ?,
                        evidence_run_id = ?,
                        results_session_number = ?,
                        base_thread_id = ?
                    WHERE audit_run_id = ?
                    """,
                    (
                        cid,
                        json.dumps(run.scope, ensure_ascii=False),
                        run.status.value,
                        run.started_at.isoformat() if run.started_at else None,
                        run.finished_at.isoformat() if run.finished_at else None,
                        run.evidence_run_id,
                        run.results_session_number,
                        run.base_thread_id,
                        run.audit_run_id,
                    ),
                )
                conn.commit()

    def transition_run(self, audit_run_id: str, new_status: AuditRunStatus) -> AuditRun:
        """Load, validate transition, persist. Raises on invalid transition."""
        run = self.get_run(audit_run_id)
        if run is None:
            raise KeyError(f"AuditRun not found: {audit_run_id}")
        if new_status == AuditRunStatus.COMPLETED:
            jobs = self.list_jobs(audit_run_id)
            ok, reason = can_complete_run(jobs)
            if not ok:
                raise InvalidStatusTransition(f"cannot complete AuditRun {audit_run_id}: {reason}")
        run.transition_to(new_status)
        self.save_run(run)
        return run

    def mark_run_started(self, audit_run_id: str) -> AuditRun:
        return self.transition_run(audit_run_id, AuditRunStatus.RUNNING)

    def mark_run_cancelled(self, audit_run_id: str) -> AuditRun:
        return self.transition_run(audit_run_id, AuditRunStatus.CANCELLED)

    def cancel_run(self, audit_run_id: str) -> AuditRun:
        """Cancel open jobs and the run; keeps the same ``audit_run_id``."""
        run = self.get_run(audit_run_id)
        if run is None:
            raise KeyError(f"AuditRun not found: {audit_run_id}")
        for job in self.list_jobs(audit_run_id):
            if job.status in {
                AuditJobStatus.PENDING,
                AuditJobStatus.RUNNING,
            }:
                self.transition_job(job.job_id, AuditJobStatus.CANCELLED)
        if run.status == AuditRunStatus.CANCELLED:
            return run
        return self.mark_run_cancelled(audit_run_id)

    def resume_run(self, audit_run_id: str) -> AuditRun:
        """Resume a cancelled run (same id); does not invent a new run."""
        run = self.get_run(audit_run_id)
        if run is None:
            raise KeyError(f"AuditRun not found: {audit_run_id}")
        if run.status == AuditRunStatus.RUNNING:
            return run
        return self.transition_run(audit_run_id, AuditRunStatus.RUNNING)

    def finalize_run(self, audit_run_id: str) -> AuditRun:
        """Set terminal status from job outcomes (completed/partial/failed)."""
        run = self.get_run(audit_run_id)
        if run is None:
            raise KeyError(f"AuditRun not found: {audit_run_id}")
        jobs = self.list_jobs(audit_run_id)
        terminal = resolve_terminal_run_status(jobs)
        if terminal == AuditRunStatus.COMPLETED:
            ok, reason = can_complete_run(jobs)
            if not ok:
                raise InvalidStatusTransition(f"cannot complete AuditRun {audit_run_id}: {reason}")
        run.transition_to(terminal)
        self.save_run(run)
        return run

    # --- jobs -----------------------------------------------------------------

    def create_job(
        self,
        *,
        audit_run_id: str,
        logical_task_id: str,
        job_type: AuditJobType = AuditJobType.ASSESS_FRAMEWORK,
        mandatory: bool = True,
        thread_id: str = "",
        framework_id: str = "",
        host_id: str = "",
        attempt: int | None = None,
    ) -> AuditJob:
        """Create a pending job attempt (retry → higher attempt, same run)."""
        if self.get_run(audit_run_id) is None:
            raise KeyError(f"AuditRun not found: {audit_run_id}")
        if attempt is None:
            attempt = self.next_attempt(audit_run_id, logical_task_id)
        job = AuditJob(
            job_id=new_job_id(),
            audit_run_id=audit_run_id,
            job_type=job_type,
            logical_task_id=logical_task_id,
            attempt=attempt,
            mandatory=mandatory,
            thread_id=thread_id,
            framework_id=framework_id,
            host_id=host_id,
        )
        with self._lock:
            with self._connect() as conn:
                self._insert_job(conn, job)
                conn.commit()
        return job

    def next_attempt(self, audit_run_id: str, logical_task_id: str) -> int:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT COALESCE(MAX(attempt), 0) AS m
                    FROM audit_jobs
                    WHERE audit_run_id = ? AND logical_task_id = ?
                    """,
                    (audit_run_id, logical_task_id),
                ).fetchone()
        return int(row["m"] if row else 0) + 1

    def get_job(self, job_id: str) -> AuditJob | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM audit_jobs WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
        return self._row_to_job(row) if row else None

    def list_jobs(self, audit_run_id: str) -> list[AuditJob]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM audit_jobs
                    WHERE audit_run_id = ?
                    ORDER BY logical_task_id, attempt
                    """,
                    (audit_run_id,),
                ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def latest_job_for_task(self, audit_run_id: str, logical_task_id: str) -> AuditJob | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM audit_jobs
                    WHERE audit_run_id = ? AND logical_task_id = ?
                    ORDER BY attempt DESC LIMIT 1
                    """,
                    (audit_run_id, logical_task_id),
                ).fetchone()
        return self._row_to_job(row) if row else None

    def save_job(self, job: AuditJob) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE audit_jobs SET
                        status = ?,
                        started_at = ?,
                        finished_at = ?,
                        error_json = ?,
                        thread_id = ?,
                        framework_id = ?,
                        host_id = ?,
                        mandatory = ?
                    WHERE job_id = ?
                    """,
                    (
                        job.status.value,
                        job.started_at.isoformat() if job.started_at else None,
                        job.finished_at.isoformat() if job.finished_at else None,
                        json.dumps(job.error.to_dict(), ensure_ascii=False) if job.error else None,
                        job.thread_id,
                        job.framework_id,
                        job.host_id,
                        1 if job.mandatory else 0,
                        job.job_id,
                    ),
                )
                conn.commit()

    def transition_job(
        self,
        job_id: str,
        new_status: AuditJobStatus,
        *,
        error: JobErrorInfo | None = None,
    ) -> AuditJob:
        job = self.get_job(job_id)
        if job is None:
            raise KeyError(f"AuditJob not found: {job_id}")
        job.transition_to(new_status, error=error)
        self.save_job(job)
        return job

    def start_job_attempt(
        self,
        *,
        audit_run_id: str,
        logical_task_id: str,
        thread_id: str = "",
        framework_id: str = "",
        host_id: str = "",
        mandatory: bool = True,
        job_type: AuditJobType = AuditJobType.ASSESS_FRAMEWORK,
        new_attempt: bool = False,
    ) -> AuditJob:
        """Mark latest pending job running, or create a new attempt (retry)."""
        latest = self.latest_job_for_task(audit_run_id, logical_task_id)
        if (
            new_attempt
            or latest is None
            or latest.status
            not in {
                AuditJobStatus.PENDING,
            }
        ):
            # Retry / first create
            if latest is not None and latest.status == AuditJobStatus.RUNNING:
                # Cancel previous running attempt before retrying
                latest.transition_to(AuditJobStatus.CANCELLED)
                self.save_job(latest)
            job = self.create_job(
                audit_run_id=audit_run_id,
                logical_task_id=logical_task_id,
                job_type=job_type,
                mandatory=mandatory,
                thread_id=thread_id,
                framework_id=framework_id,
                host_id=host_id,
            )
        else:
            job = latest
            if thread_id:
                job.thread_id = thread_id
            if framework_id:
                job.framework_id = framework_id
            if host_id:
                job.host_id = host_id
        return self.transition_job(job.job_id, AuditJobStatus.RUNNING)

    def complete_job(self, job_id: str) -> AuditJob:
        return self.transition_job(job_id, AuditJobStatus.COMPLETED)

    def fail_job(self, job_id: str, error: JobErrorInfo | BaseException) -> AuditJob:
        info = error if isinstance(error, JobErrorInfo) else JobErrorInfo.from_exception(error)
        return self.transition_job(job_id, AuditJobStatus.FAILED, error=info)

    def retry_job(
        self,
        *,
        audit_run_id: str,
        logical_task_id: str,
        thread_id: str = "",
        framework_id: str = "",
        host_id: str = "",
        mandatory: bool = True,
    ) -> AuditJob:
        """Create a new attempt under the same run and mark it running."""
        return self.start_job_attempt(
            audit_run_id=audit_run_id,
            logical_task_id=logical_task_id,
            thread_id=thread_id,
            framework_id=framework_id,
            host_id=host_id,
            mandatory=mandatory,
            new_attempt=True,
        )

    # --- serialization helpers ------------------------------------------------

    def _insert_run(self, conn: sqlite3.Connection, run: AuditRun) -> None:
        conn.execute(
            """
            INSERT INTO audit_runs (
                audit_run_id, client_id, scope_json, status,
                created_at, started_at, finished_at,
                evidence_run_id, results_session_number, base_thread_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.audit_run_id,
                run.client_id,
                json.dumps(run.scope, ensure_ascii=False),
                run.status.value,
                run.created_at.isoformat(),
                run.started_at.isoformat() if run.started_at else None,
                run.finished_at.isoformat() if run.finished_at else None,
                run.evidence_run_id,
                run.results_session_number,
                run.base_thread_id,
            ),
        )

    def _insert_job(self, conn: sqlite3.Connection, job: AuditJob) -> None:
        conn.execute(
            """
            INSERT INTO audit_jobs (
                job_id, audit_run_id, job_type, logical_task_id, attempt,
                status, mandatory, started_at, finished_at, error_json,
                thread_id, framework_id, host_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job.job_id,
                job.audit_run_id,
                job.job_type.value,
                job.logical_task_id,
                job.attempt,
                job.status.value,
                1 if job.mandatory else 0,
                job.started_at.isoformat() if job.started_at else None,
                job.finished_at.isoformat() if job.finished_at else None,
                json.dumps(job.error.to_dict(), ensure_ascii=False) if job.error else None,
                job.thread_id,
                job.framework_id,
                job.host_id,
            ),
        )

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> AuditRun:
        return AuditRun.from_dict(
            {
                "audit_run_id": row["audit_run_id"],
                "client_id": row["client_id"],
                "scope": json.loads(row["scope_json"] or "{}"),
                "status": row["status"],
                "created_at": row["created_at"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "evidence_run_id": row["evidence_run_id"],
                "results_session_number": row["results_session_number"],
                "base_thread_id": row["base_thread_id"],
            }
        )

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> AuditJob:
        err = None
        if row["error_json"]:
            err = json.loads(row["error_json"])
        return AuditJob.from_dict(
            {
                "job_id": row["job_id"],
                "audit_run_id": row["audit_run_id"],
                "job_type": row["job_type"],
                "logical_task_id": row["logical_task_id"],
                "attempt": row["attempt"],
                "status": row["status"],
                "mandatory": bool(row["mandatory"]),
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "error": err,
                "thread_id": row["thread_id"],
                "framework_id": row["framework_id"],
                "host_id": row["host_id"],
            }
        )


def registry_path(evidence_dir: Path | str) -> Path:
    """Default SQLite path for the audit registry."""
    return Path(evidence_dir) / ".audit_registry.sqlite"


def get_audit_registry(evidence_dir: Path | str) -> AuditRegistry:
    """Return a registry bound to ``evidence_dir``."""
    return AuditRegistry(registry_path(evidence_dir))

"""Domain models: AuditRun vs AuditJob (CORE-002).

Business-level audit runs are distinct from per-worker job attempts.
Retries create a new ``AuditJob`` under the same ``AuditRun``; a full
restart allocates a new ``AuditRun``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditRunStatus(str, Enum):
    """Lifecycle status for an :class:`AuditRun`."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"  # terminal: mandatory jobs OK; optional jobs failed


class AuditJobStatus(str, Enum):
    """Lifecycle status for an :class:`AuditJob` attempt."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class AuditJobType(str, Enum):
    """Stable job kinds under an audit run."""

    ASSESS_FRAMEWORK = "assess_framework"
    DISCOVER_HOST = "discover_host"
    INTAKE = "intake"


# Allowed status transitions (from → frozenset of to).
AUDIT_RUN_TRANSITIONS: dict[AuditRunStatus, frozenset[AuditRunStatus]] = {
    AuditRunStatus.PENDING: frozenset({AuditRunStatus.RUNNING, AuditRunStatus.CANCELLED}),
    AuditRunStatus.RUNNING: frozenset(
        {
            AuditRunStatus.COMPLETED,
            AuditRunStatus.FAILED,
            AuditRunStatus.CANCELLED,
            AuditRunStatus.PARTIAL,
        }
    ),
    AuditRunStatus.COMPLETED: frozenset(),
    AuditRunStatus.FAILED: frozenset(),
    # Resume after cancel continues the same AuditRun (CORE-002).
    AuditRunStatus.CANCELLED: frozenset({AuditRunStatus.RUNNING}),
    AuditRunStatus.PARTIAL: frozenset(),
}

AUDIT_JOB_TRANSITIONS: dict[AuditJobStatus, frozenset[AuditJobStatus]] = {
    AuditJobStatus.PENDING: frozenset(
        {
            AuditJobStatus.RUNNING,
            AuditJobStatus.CANCELLED,
            AuditJobStatus.SKIPPED,
        }
    ),
    AuditJobStatus.RUNNING: frozenset(
        {
            AuditJobStatus.COMPLETED,
            AuditJobStatus.FAILED,
            AuditJobStatus.CANCELLED,
        }
    ),
    AuditJobStatus.COMPLETED: frozenset(),
    AuditJobStatus.FAILED: frozenset(),
    AuditJobStatus.CANCELLED: frozenset(),
    AuditJobStatus.SKIPPED: frozenset(),
}

# Terminal statuses that block a run from becoming COMPLETED if mandatory.
_JOB_BLOCKS_RUN_COMPLETED = frozenset(
    {
        AuditJobStatus.PENDING,
        AuditJobStatus.RUNNING,
        AuditJobStatus.FAILED,
        AuditJobStatus.CANCELLED,
    }
)


class InvalidStatusTransition(ValueError):
    """Raised when a run/job status change is not allowed."""


def validate_run_transition(current: AuditRunStatus, new: AuditRunStatus) -> None:
    """Raise :class:`InvalidStatusTransition` when ``current → new`` is illegal."""
    if current == new:
        return
    allowed = AUDIT_RUN_TRANSITIONS.get(current, frozenset())
    if new not in allowed:
        raise InvalidStatusTransition(
            f"AuditRun status {current.value!r} → {new.value!r} is not allowed"
        )


def validate_job_transition(current: AuditJobStatus, new: AuditJobStatus) -> None:
    """Raise :class:`InvalidStatusTransition` when ``current → new`` is illegal."""
    if current == new:
        return
    allowed = AUDIT_JOB_TRANSITIONS.get(current, frozenset())
    if new not in allowed:
        raise InvalidStatusTransition(
            f"AuditJob status {current.value!r} → {new.value!r} is not allowed"
        )


def new_audit_run_id() -> str:
    """Return a new opaque audit run id."""
    return f"arun_{uuid4().hex[:16]}"


def new_job_id() -> str:
    """Return a new opaque job attempt id."""
    return f"ajob_{uuid4().hex[:16]}"


@dataclass(slots=True)
class JobErrorInfo:
    """Structured error payload for a failed job attempt."""

    error_type: str = ""
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_type": self.error_type,
            "message": self.message,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> JobErrorInfo | None:
        if not data:
            return None
        return cls(
            error_type=str(data.get("error_type") or ""),
            message=str(data.get("message") or ""),
            details=dict(data.get("details") or {}),
        )

    @classmethod
    def from_exception(cls, exc: BaseException) -> JobErrorInfo:
        return cls(error_type=type(exc).__name__, message=str(exc))


@dataclass(slots=True)
class AuditRun:
    """Business-level audit execution for one client scope."""

    audit_run_id: str
    client_id: str
    scope: dict[str, Any] = field(default_factory=dict)
    status: AuditRunStatus = AuditRunStatus.PENDING
    created_at: datetime = field(default_factory=_utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    # Cross-links to existing evidence / warehouse identity (compat).
    evidence_run_id: str = ""
    results_session_number: int | None = None
    base_thread_id: str = ""

    def transition_to(self, new_status: AuditRunStatus) -> None:
        """Apply a validated status change and timestamps."""
        validate_run_transition(self.status, new_status)
        now = _utcnow()
        if new_status == AuditRunStatus.RUNNING:
            if self.started_at is None:
                self.started_at = now
            # Resume after cancel clears terminal timestamp.
            self.finished_at = None
        if new_status in {
            AuditRunStatus.COMPLETED,
            AuditRunStatus.FAILED,
            AuditRunStatus.CANCELLED,
            AuditRunStatus.PARTIAL,
        }:
            self.finished_at = now
        self.status = new_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_run_id": self.audit_run_id,
            "client_id": self.client_id,
            "scope": dict(self.scope),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": (self.finished_at.isoformat() if self.finished_at else None),
            "evidence_run_id": self.evidence_run_id,
            "results_session_number": self.results_session_number,
            "base_thread_id": self.base_thread_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditRun:
        def _ts(key: str) -> datetime | None:
            raw = data.get(key)
            if not raw:
                return None
            return datetime.fromisoformat(str(raw))

        return cls(
            audit_run_id=str(data["audit_run_id"]),
            client_id=str(data.get("client_id") or ""),
            scope=dict(data.get("scope") or {}),
            status=AuditRunStatus(str(data.get("status") or "pending")),
            created_at=_ts("created_at") or _utcnow(),
            started_at=_ts("started_at"),
            finished_at=_ts("finished_at"),
            evidence_run_id=str(data.get("evidence_run_id") or ""),
            results_session_number=(
                int(data["results_session_number"])
                if data.get("results_session_number") is not None
                else None
            ),
            base_thread_id=str(data.get("base_thread_id") or ""),
        )


@dataclass(slots=True)
class AuditJob:
    """One worker attempt under an :class:`AuditRun`."""

    job_id: str
    audit_run_id: str
    job_type: AuditJobType
    logical_task_id: str
    attempt: int = 1
    status: AuditJobStatus = AuditJobStatus.PENDING
    mandatory: bool = True
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: JobErrorInfo | None = None
    thread_id: str = ""
    framework_id: str = ""
    host_id: str = ""

    def transition_to(
        self,
        new_status: AuditJobStatus,
        *,
        error: JobErrorInfo | None = None,
    ) -> None:
        """Apply a validated status change and optional error payload."""
        validate_job_transition(self.status, new_status)
        now = _utcnow()
        if new_status == AuditJobStatus.RUNNING and self.started_at is None:
            self.started_at = now
        if new_status in {
            AuditJobStatus.COMPLETED,
            AuditJobStatus.FAILED,
            AuditJobStatus.CANCELLED,
            AuditJobStatus.SKIPPED,
        }:
            self.finished_at = now
        if error is not None:
            self.error = error
        self.status = new_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "audit_run_id": self.audit_run_id,
            "job_type": self.job_type.value,
            "logical_task_id": self.logical_task_id,
            "attempt": self.attempt,
            "status": self.status.value,
            "mandatory": self.mandatory,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": (self.finished_at.isoformat() if self.finished_at else None),
            "error": self.error.to_dict() if self.error else None,
            "thread_id": self.thread_id,
            "framework_id": self.framework_id,
            "host_id": self.host_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditJob:
        def _ts(key: str) -> datetime | None:
            raw = data.get(key)
            if not raw:
                return None
            return datetime.fromisoformat(str(raw))

        return cls(
            job_id=str(data["job_id"]),
            audit_run_id=str(data["audit_run_id"]),
            job_type=AuditJobType(str(data.get("job_type") or "assess_framework")),
            logical_task_id=str(data.get("logical_task_id") or ""),
            attempt=int(data.get("attempt") or 1),
            status=AuditJobStatus(str(data.get("status") or "pending")),
            mandatory=bool(data.get("mandatory", True)),
            started_at=_ts("started_at"),
            finished_at=_ts("finished_at"),
            error=JobErrorInfo.from_dict(
                data.get("error") if isinstance(data.get("error"), dict) else None
            ),
            thread_id=str(data.get("thread_id") or ""),
            framework_id=str(data.get("framework_id") or ""),
            host_id=str(data.get("host_id") or ""),
        )


def latest_jobs_by_task(jobs: list[AuditJob]) -> list[AuditJob]:
    """Keep only the highest attempt per ``logical_task_id``."""
    by_task: dict[str, AuditJob] = {}
    for job in jobs:
        prev = by_task.get(job.logical_task_id)
        if prev is None or job.attempt > prev.attempt:
            by_task[job.logical_task_id] = job
    return list(by_task.values())


def can_complete_run(jobs: list[AuditJob]) -> tuple[bool, str]:
    """Return whether a run may transition to ``completed``.

    Considers the latest attempt per logical task. Mandatory jobs must all be
    ``completed`` or ``skipped``. Failed/cancelled/pending/running mandatory
    jobs block completion.
    """
    for job in latest_jobs_by_task(jobs):
        if not job.mandatory:
            continue
        if job.status in _JOB_BLOCKS_RUN_COMPLETED:
            return (
                False,
                f"mandatory job {job.logical_task_id!r} is {job.status.value}",
            )
        if job.status not in {
            AuditJobStatus.COMPLETED,
            AuditJobStatus.SKIPPED,
        }:
            return (
                False,
                f"mandatory job {job.logical_task_id!r} has unexpected status {job.status.value}",
            )
    return True, ""


def resolve_terminal_run_status(jobs: list[AuditJob]) -> AuditRunStatus:
    """Pick COMPLETED vs PARTIAL vs FAILED from latest job outcomes.

    - COMPLETED: all mandatory jobs completed/skipped; no optional failures
    - PARTIAL: all mandatory OK; at least one optional failed/cancelled
    - FAILED: any mandatory failed/cancelled (or still unfinished)
    """
    latest = latest_jobs_by_task(jobs)
    mandatory = [j for j in latest if j.mandatory]
    optional = [j for j in latest if not j.mandatory]
    for job in mandatory:
        if job.status in {
            AuditJobStatus.FAILED,
            AuditJobStatus.CANCELLED,
            AuditJobStatus.PENDING,
            AuditJobStatus.RUNNING,
        }:
            return AuditRunStatus.FAILED
    optional_bad = any(
        j.status in {AuditJobStatus.FAILED, AuditJobStatus.CANCELLED} for j in optional
    )
    if optional_bad:
        return AuditRunStatus.PARTIAL
    return AuditRunStatus.COMPLETED

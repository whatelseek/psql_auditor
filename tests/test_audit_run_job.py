"""CORE-002: AuditRun vs AuditJob separation."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from auditor.audit_registry import get_audit_registry
from auditor.config import Settings
from auditor.domain import (
    AuditJobStatus,
    AuditJobType,
    AuditRunStatus,
    InvalidStatusTransition,
    can_complete_run,
    resolve_terminal_run_status,
    validate_job_transition,
    validate_run_transition,
)
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph
from auditor.secrets_file import InventorySshTarget


def _fw(fid: str) -> SimpleNamespace:
    return SimpleNamespace(id=fid, title=fid)


def _target(host: str) -> InventorySshTarget:
    return InventorySshTarget(host=host, user="audit")


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        max_parallel_host_jobs=4,
    )


@pytest.mark.asyncio
async def test_worker_retry_new_job_same_run(tmp_path: Path):
    """Retrying a failed worker creates a new job attempt, not a new run."""
    settings = _settings(tmp_path)
    graph = AuditorGraph(settings=settings)
    calls = {"n": 0}

    async def fake_arun_one(user_text, **kwargs):
        del user_text
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return {
            "report": "ok",
            "awaiting_hitl": False,
            "thread_id": kwargs.get("thread_id"),
            "messages": [],
        }

    jobs = [(_target("h1"), None, _fw("fw1"))]
    with (
        patch.object(graph, "arun_one", side_effect=fake_arun_one),
        patch.object(
            graph,
            "_merge_multi_reports",
            new=AsyncMock(
                side_effect=lambda completed, **kw: {
                    "report": "merged",
                    "awaiting_hitl": False,
                    "audit_run_id": kw.get("audit_run_id"),
                }
            ),
        ),
    ):
        await graph._run_framework_jobs(
            user_text="audit",
            base_thread="t-retry",
            run_id="ev-retry",
            intake_state={"client_name": "Acme", "intake_complete": True},
            jobs=jobs,
            plan_md="",
        )

        registry = get_audit_registry(tmp_path)
        arun = registry.get_run_by_evidence_id("ev-retry")
        assert arun is not None
        run_id = arun.audit_run_id
        jobs1 = registry.list_jobs(run_id)
        assert len(jobs1) == 1
        assert jobs1[0].status == AuditJobStatus.FAILED
        assert jobs1[0].attempt == 1

        # Retry same logical task under same run (scheduler path).
        second = await graph._schedule_framework_jobs(
            user_text="audit",
            base_thread="t-retry",
            run_id="ev-retry",
            intake_state={
                "client_name": "Acme",
                "intake_complete": True,
                "audit_run_id": run_id,
            },
            pending_jobs=[
                {
                    "framework_id": "fw1",
                    "framework_title": "fw1",
                    "evidence_host_id": "h1",
                }
            ],
            completed=[],
            plan_md="",
        )
        assert second.get("report") == "merged"

    arun2 = registry.get_run(run_id)
    assert arun2 is not None
    assert arun2.audit_run_id == run_id
    all_jobs = registry.list_jobs(run_id)
    assert len(all_jobs) == 2
    assert {j.attempt for j in all_jobs} == {1, 2}
    latest = registry.latest_job_for_task(run_id, "h1/fw1")
    assert latest is not None
    assert latest.attempt == 2
    assert latest.status == AuditJobStatus.COMPLETED
    # Still only one run for this evidence folder identity used in bootstraps
    assert registry.get_run_by_evidence_id("ev-retry").audit_run_id == run_id


@pytest.mark.asyncio
async def test_full_restart_creates_new_run(tmp_path: Path):
    """Restarting the entire audit allocates a new AuditRun."""
    settings = _settings(tmp_path)
    graph = AuditorGraph(settings=settings)

    async def fake_arun_one(user_text, **kwargs):
        del user_text
        return {
            "report": "ok",
            "awaiting_hitl": False,
            "thread_id": kwargs.get("thread_id"),
            "messages": [],
        }

    with (
        patch.object(graph, "arun_one", side_effect=fake_arun_one),
        patch.object(
            graph,
            "_merge_multi_reports",
            new=AsyncMock(
                return_value={"report": "merged", "awaiting_hitl": False}
            ),
        ),
    ):
        await graph._run_framework_jobs(
            user_text="audit",
            base_thread="t1",
            run_id="ev-a",
            intake_state={"client_name": "Acme", "intake_complete": True},
            jobs=[(None, None, _fw("fw1"))],
            plan_md="",
        )
        await graph._run_framework_jobs(
            user_text="audit again",
            base_thread="t2",
            run_id="ev-b",
            intake_state={"client_name": "Acme", "intake_complete": True},
            jobs=[(None, None, _fw("fw1"))],
            plan_md="",
        )

    registry = get_audit_registry(tmp_path)
    a = registry.get_run_by_evidence_id("ev-a")
    b = registry.get_run_by_evidence_id("ev-b")
    assert a is not None and b is not None
    assert a.audit_run_id != b.audit_run_id


@pytest.mark.asyncio
async def test_attempt_numbers_increase(tmp_path: Path):
    """Attempt numbers increase for the same logical job under one run."""
    registry = get_audit_registry(tmp_path)
    run = registry.create_run(client_id="acme", evidence_run_id="ev")
    registry.mark_run_started(run.audit_run_id)
    j1 = registry.create_job(
        audit_run_id=run.audit_run_id,
        logical_task_id="h1/fw1",
        job_type=AuditJobType.ASSESS_FRAMEWORK,
    )
    assert j1.attempt == 1
    registry.start_job_attempt(
        audit_run_id=run.audit_run_id,
        logical_task_id="h1/fw1",
        new_attempt=False,
    )
    registry.fail_job(j1.job_id, RuntimeError("x"))
    j2 = registry.retry_job(
        audit_run_id=run.audit_run_id, logical_task_id="h1/fw1"
    )
    assert j2.attempt == 2
    registry.fail_job(j2.job_id, RuntimeError("y"))
    j3 = registry.retry_job(
        audit_run_id=run.audit_run_id, logical_task_id="h1/fw1"
    )
    assert j3.attempt == 3
    assert j1.audit_run_id == j2.audit_run_id == j3.audit_run_id


@pytest.mark.asyncio
async def test_concurrent_runs_do_not_mix_jobs(tmp_path: Path):
    """Two concurrent AuditRuns keep job rows isolated."""
    settings = _settings(tmp_path)
    graph = AuditorGraph(settings=settings)
    seen: dict[str, str] = {}

    async def fake_arun_one(user_text, **kwargs):
        del user_text
        intake = kwargs.get("intake_state") or {}
        ar = str(intake.get("audit_run_id") or "")
        host = str(kwargs.get("evidence_host_id") or "")
        seen[f"{ar}:{host}"] = ar
        await asyncio.sleep(0.02)
        return {
            "report": "ok",
            "awaiting_hitl": False,
            "thread_id": kwargs.get("thread_id"),
            "messages": [],
        }

    with (
        patch.object(graph, "arun_one", side_effect=fake_arun_one),
        patch.object(
            graph,
            "_merge_multi_reports",
            new=AsyncMock(
                return_value={"report": "merged", "awaiting_hitl": False}
            ),
        ),
    ):
        await asyncio.gather(
            graph._run_framework_jobs(
                user_text="a",
                base_thread="ta",
                run_id="ev-1",
                intake_state={"client_name": "A", "intake_complete": True},
                jobs=[(_target("ha"), None, _fw("fw1"))],
                plan_md="",
            ),
            graph._run_framework_jobs(
                user_text="b",
                base_thread="tb",
                run_id="ev-2",
                intake_state={"client_name": "B", "intake_complete": True},
                jobs=[(_target("hb"), None, _fw("fw1"))],
                plan_md="",
            ),
        )

    registry = get_audit_registry(tmp_path)
    r1 = registry.get_run_by_evidence_id("ev-1")
    r2 = registry.get_run_by_evidence_id("ev-2")
    assert r1 and r2 and r1.audit_run_id != r2.audit_run_id
    j1 = registry.list_jobs(r1.audit_run_id)
    j2 = registry.list_jobs(r2.audit_run_id)
    assert len(j1) == 1 and len(j2) == 1
    assert j1[0].logical_task_id == "ha/fw1"
    assert j2[0].logical_task_id == "hb/fw1"
    assert j1[0].audit_run_id != j2[0].audit_run_id


def test_run_cannot_complete_while_mandatory_unfinished(tmp_path: Path):
    """completed is rejected while mandatory jobs are unfinished or failed."""
    registry = get_audit_registry(tmp_path)
    run = registry.create_run(client_id="acme")
    registry.mark_run_started(run.audit_run_id)
    job = registry.create_job(
        audit_run_id=run.audit_run_id, logical_task_id="fw1"
    )
    registry.transition_job(job.job_id, AuditJobStatus.RUNNING)

    with pytest.raises(InvalidStatusTransition):
        registry.transition_run(run.audit_run_id, AuditRunStatus.COMPLETED)

    registry.fail_job(job.job_id, RuntimeError("nope"))
    with pytest.raises(InvalidStatusTransition):
        registry.transition_run(run.audit_run_id, AuditRunStatus.COMPLETED)

    ok, reason = can_complete_run(registry.list_jobs(run.audit_run_id))
    assert ok is False
    assert "failed" in reason or "fw1" in reason

    # Optional failure → PARTIAL terminal is allowed when mandatory OK.
    run2 = registry.create_run(client_id="acme2")
    registry.mark_run_started(run2.audit_run_id)
    mand = registry.create_job(
        audit_run_id=run2.audit_run_id, logical_task_id="m1", mandatory=True
    )
    opt = registry.create_job(
        audit_run_id=run2.audit_run_id, logical_task_id="o1", mandatory=False
    )
    registry.transition_job(mand.job_id, AuditJobStatus.RUNNING)
    registry.complete_job(mand.job_id)
    registry.transition_job(opt.job_id, AuditJobStatus.RUNNING)
    registry.fail_job(opt.job_id, RuntimeError("optional"))
    assert (
        resolve_terminal_run_status(registry.list_jobs(run2.audit_run_id))
        == AuditRunStatus.PARTIAL
    )
    finalized = registry.finalize_run(run2.audit_run_id)
    assert finalized.status == AuditRunStatus.PARTIAL


def test_cancel_and_resume_preserve_audit_run_id(tmp_path: Path):
    """Cancel/resume operate on the existing AuditRun id."""
    settings = _settings(tmp_path)
    graph = AuditorGraph(settings=settings)
    registry = get_audit_registry(tmp_path)
    run = registry.create_run(client_id="acme", evidence_run_id="ev-c")
    registry.mark_run_started(run.audit_run_id)
    job = registry.create_job(
        audit_run_id=run.audit_run_id, logical_task_id="fw1"
    )
    registry.transition_job(job.job_id, AuditJobStatus.RUNNING)

    cancelled = graph.cancel_audit_run(run.audit_run_id)
    assert cancelled.audit_run_id == run.audit_run_id
    assert cancelled.status == AuditRunStatus.CANCELLED
    assert registry.get_job(job.job_id).status == AuditJobStatus.CANCELLED

    resumed = graph.resume_audit_run(run.audit_run_id)
    assert resumed.audit_run_id == run.audit_run_id
    assert resumed.status == AuditRunStatus.RUNNING


def test_invalid_status_transitions_rejected():
    """Illegal run/job transitions raise InvalidStatusTransition."""
    with pytest.raises(InvalidStatusTransition):
        validate_run_transition(
            AuditRunStatus.COMPLETED, AuditRunStatus.RUNNING
        )
    with pytest.raises(InvalidStatusTransition):
        validate_job_transition(
            AuditJobStatus.COMPLETED, AuditJobStatus.FAILED
        )
    with pytest.raises(InvalidStatusTransition):
        validate_job_transition(
            AuditJobStatus.PENDING, AuditJobStatus.COMPLETED
        )


@pytest.mark.asyncio
async def test_production_path_records_audit_run_in_meta(tmp_path: Path):
    """Execution path persists audit_run_id (not models-only)."""
    settings = _settings(tmp_path)
    graph = AuditorGraph(settings=settings)
    store = EvidenceStore(tmp_path, run_id="ev-meta")
    graph._evidence_by_run["ev-meta"] = store

    async def fake_arun_one(user_text, **kwargs):
        del user_text
        return {
            "report": "ok",
            "awaiting_hitl": False,
            "thread_id": kwargs.get("thread_id"),
            "messages": [],
        }

    with patch.object(graph, "arun_one", side_effect=fake_arun_one):
        result = await graph._run_framework_jobs(
            user_text="audit",
            base_thread="t-meta",
            run_id="ev-meta",
            intake_state={"client_name": "Acme", "intake_complete": True},
            jobs=[(None, None, _fw("fw1"))],
            plan_md="",
        )

    meta = store.read_run_meta()
    assert meta.get("audit_run_id")
    assert result.get("audit_run_id") == meta["audit_run_id"]
    registry = get_audit_registry(tmp_path)
    arun = registry.get_run(str(meta["audit_run_id"]))
    assert arun is not None
    assert arun.status == AuditRunStatus.COMPLETED
    jobs = registry.list_jobs(arun.audit_run_id)
    assert len(jobs) == 1
    assert jobs[0].status == AuditJobStatus.COMPLETED

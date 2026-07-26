"""Tests for cross-host parallel framework job scheduling."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from tests.helpers.audit_request import intake_with_request

from auditor.client_registry import get_client_registry
from auditor.config import Settings
from auditor.evidence_store import EvidenceStore, bind_host_segment, effective_host_segment
from auditor.graph import AuditorGraph
from auditor.secrets_file import InventorySshTarget


def _fw(fid: str, title: str | None = None) -> SimpleNamespace:
    """Minimal framework-like object for scheduler tests."""
    return SimpleNamespace(id=fid, title=title or fid)


def _target(host: str) -> InventorySshTarget:
    """Build a bare SSH inventory target."""
    return InventorySshTarget(host=host, user="audit")


@pytest.mark.asyncio
async def test_bind_host_segment_context_isolated(tmp_path: Path):
    """Concurrent ContextVar host binds must not clobber each other."""
    store = EvidenceStore(tmp_path, run_id="seg-test")
    seen: dict[str, str | None] = {}

    async def _worker(host: str) -> None:
        with bind_host_segment(host):
            await asyncio.sleep(0.02)
            seen[host] = effective_host_segment(store.host_segment)

    await asyncio.gather(_worker("10.0.0.1"), _worker("10.0.0.2"))
    assert seen["10.0.0.1"] == "10.0.0.1"
    assert seen["10.0.0.2"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_schedule_respects_host_lock_and_concurrency(tmp_path: Path):
    """Jobs on A,A,B with cap 2: B overlaps first A; second A waits; peak ≤ 2."""
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        max_parallel_host_jobs=2,
        agents_dir=Path("agents"),
    )
    graph = AuditorGraph(settings=settings)
    client = get_client_registry(tmp_path).ensure_client(display_name="Acme", slug="acme")

    current = 0
    peak = 0
    lock = asyncio.Lock()
    active_hosts: list[str] = []
    host_overlap_violation = False
    started_order: list[str] = []
    finished_order: list[str] = []

    async def fake_arun_one(user_text, **kwargs):
        nonlocal current, peak, host_overlap_violation
        del user_text
        host = str(kwargs.get("evidence_host_id") or "")
        fw = str(kwargs.get("framework_id") or "")
        key = f"{host}/{fw}" if host else fw
        async with lock:
            started_order.append(key)
            if host and host in active_hosts:
                host_overlap_violation = True
            active_hosts.append(host)
            current += 1
            peak = max(peak, current)
        # A jobs take longer so B can overlap the first A.
        await asyncio.sleep(0.08 if host == "host-a" else 0.03)
        async with lock:
            current -= 1
            active_hosts.remove(host)
            finished_order.append(key)
        return {
            "report": f"ok {key}",
            "awaiting_hitl": False,
            "thread_id": kwargs.get("thread_id"),
            "messages": [],
        }

    jobs = [
        (_target("host-a"), None, _fw("fw1")),
        (_target("host-a"), None, _fw("fw2")),
        (_target("host-b"), None, _fw("fw1")),
    ]
    with (
        patch.object(graph, "arun_one", side_effect=fake_arun_one),
        patch.object(
            graph,
            "_merge_multi_reports",
            new=AsyncMock(
                side_effect=lambda completed, **_k: {
                    "report": "merged:" + ",".join(c[0] for c in completed),
                    "awaiting_hitl": False,
                }
            ),
        ),
    ):
        result = await graph._run_framework_jobs(
            user_text="audit",
            base_thread="t-parallel",
            run_id="run-parallel",
            intake_state=intake_with_request(client.client_id, host="host-a", framework_id="fw1"),
            jobs=jobs,
            plan_md="",
        )

    assert peak <= 2
    assert not host_overlap_violation
    assert "host-a/fw1" in started_order
    assert "host-b/fw1" in started_order
    # Second A job must not start before first A finishes.
    assert started_order.index("host-a/fw2") > finished_order.index("host-a/fw1")
    assert result["report"].startswith("merged:")
    assert "host-a/fw1" in result["report"]
    assert "host-b/fw1" in result["report"]


@pytest.mark.asyncio
async def test_schedule_hitl_drains_inflight_and_keeps_remaining(tmp_path: Path):
    """HITL on one job stops new starts, drains peers, keeps remaining queue."""
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        max_parallel_host_jobs=2,
        agents_dir=Path("agents"),
    )
    graph = AuditorGraph(settings=settings)
    client = get_client_registry(tmp_path).ensure_client(display_name="Acme", slug="acme")
    calls: list[str] = []

    async def fake_arun_one(user_text, **kwargs):
        del user_text
        host = str(kwargs.get("evidence_host_id") or "")
        fw = str(kwargs.get("framework_id") or "")
        key = f"{host}/{fw}"
        calls.append(key)
        if key == "host-a/fw1":
            await asyncio.sleep(0.02)
            return {
                "report": "HITL A",
                "awaiting_hitl": True,
                "thread_id": kwargs.get("thread_id"),
                "messages": [],
            }
        await asyncio.sleep(0.05)
        return {
            "report": f"ok {key}",
            "awaiting_hitl": False,
            "thread_id": kwargs.get("thread_id"),
            "messages": [],
        }

    jobs = [
        (_target("host-a"), None, _fw("fw1")),
        (_target("host-b"), None, _fw("fw1")),
        (_target("host-c"), None, _fw("fw1")),
    ]
    with patch.object(graph, "arun_one", side_effect=fake_arun_one):
        result = await graph._run_framework_jobs(
            user_text="audit",
            base_thread="t-hitl",
            run_id="run-hitl",
            intake_state=intake_with_request(client.client_id, host="host-a", framework_id="fw1"),
            jobs=jobs,
            plan_md="# Plan",
        )

    assert result.get("awaiting_hitl") is True
    assert "host-a/fw1" in calls
    assert "host-b/fw1" in calls
    # host-c must not start after HITL stop_starting
    assert "host-c/fw1" not in calls
    tid = str(result.get("thread_id") or "")
    assert tid.endswith("host-a:fw1") or "host-a" in tid
    session = graph._multi_sessions.get(tid)
    assert session is not None
    remaining_keys = [graph._job_dict_key(j) for j in (session.get("remaining_jobs") or [])]
    assert remaining_keys == ["host-c/fw1"]
    # Peer host-b completed during drain
    completed_keys = [c[0] for c in (session.get("completed") or [])]
    assert "host-b/fw1" in completed_keys


@pytest.mark.asyncio
async def test_continue_after_resume_surfaces_sibling_hitl():
    """After one HITL resume completes, a sibling pause is returned next."""
    settings = Settings(
        _env_file=None,
        max_parallel_host_jobs=2,
        agents_dir=Path("agents"),
    )
    graph = AuditorGraph(settings=settings)
    base = "t-sib"
    run_id = "run-sib"
    tid_a = f"{base}:host-a:fw1"
    tid_b = f"{base}:host-b:fw1"
    graph._remember_multi_session(
        tid_a,
        {
            "base_thread": base,
            "run_id": run_id,
            "user_text": "audit",
            "framework_id": "fw1",
            "framework_title": "fw1",
            "job_key": "host-a/fw1",
            "evidence_host_id": "host-a",
            "remaining_jobs": [
                {
                    "framework_id": "fw1",
                    "framework_title": "fw1",
                    "evidence_host_id": "host-c",
                    "ssh_host": "host-c",
                    "ssh_port": "22",
                    "ssh_user": "",
                    "ssh_password": "",
                    "ssh_key": "",
                    "ssh_strict": "",
                    "ssh_label": "",
                }
            ],
            "remaining": ["fw1"],
            "completed": [],
            "intake_state": {},
            "plan_md": "",
            "paused_siblings": [
                {
                    "thread_id": tid_b,
                    "job_key": "host-b/fw1",
                    "framework_id": "fw1",
                    "framework_title": "fw1",
                    "evidence_host_id": "host-b",
                }
            ],
            "hitl_report": "HITL A",
            "parallel_scheduler": True,
        },
    )
    graph._remember_multi_session(
        tid_b,
        {
            "base_thread": base,
            "run_id": run_id,
            "user_text": "audit",
            "framework_id": "fw1",
            "framework_title": "fw1",
            "job_key": "host-b/fw1",
            "evidence_host_id": "host-b",
            "remaining_jobs": [],
            "remaining": [],
            "completed": [],
            "intake_state": {},
            "plan_md": "",
            "paused_siblings": [
                {
                    "thread_id": tid_a,
                    "job_key": "host-a/fw1",
                    "framework_id": "fw1",
                    "framework_title": "fw1",
                    "evidence_host_id": "host-a",
                }
            ],
            "hitl_report": "HITL B body",
            "parallel_scheduler": True,
        },
    )

    result = await graph._continue_multi_after_resume(
        tid_a,
        {"report": "A done", "awaiting_hitl": False},
    )
    assert result.get("awaiting_hitl") is True
    assert result.get("thread_id") == tid_b
    assert "HITL B body" in str(result.get("report") or "")
    assert "host-a/fw1" in str(result.get("report") or "")

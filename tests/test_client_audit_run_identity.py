"""CORE-001: Separate persistent client_id from audit_run_id."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry, looks_like_audit_run_id
from auditor.config import Settings
from auditor.domain import AuditRunStatus, new_audit_run_id
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph
from auditor.legacy_compat import (
    AmbiguousLegacyRunError,
    MissingAuditRunIdError,
    report_legacy_without_audit_run,
    require_audit_run_id,
    resolve_evidence_for_audit_run,
)
from auditor.secrets_file import InventorySshTarget


def _fw(fid: str) -> SimpleNamespace:
    return SimpleNamespace(id=fid, title=fid, version="1.0")


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
async def test_two_audits_same_client_reuse_client_id_new_run(tmp_path: Path):
    """Two new audits for the same client reuse client_id, different audit_run_id."""
    settings = _settings(tmp_path)
    clients = get_client_registry(tmp_path)
    c1 = clients.ensure_client(display_name="Acme Corp", slug="acme_corp")
    c2 = clients.ensure_client(display_name="Acme Corp", slug="acme_corp")
    assert c1.client_id == c2.client_id

    graph = AuditorGraph(settings=settings)
    registry = get_audit_registry(tmp_path)

    async def fake_arun_one(user_text, **kwargs):
        del user_text
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
                    "client_id": kw.get("client_id"),
                }
            ),
        ),
    ):
        for i, ev in enumerate(("ev-a", "ev-b")):
            await graph._run_framework_jobs(
                user_text="audit",
                base_thread=f"t-{i}",
                run_id=ev,
                intake_state={
                    "client_name": "Acme Corp",
                    "client_slug": "acme_corp",
                    "client_id": c1.client_id,
                    "intake_complete": True,
                },
                jobs=jobs,
                plan_md="",
            )

    runs = [r for r in _list_runs(registry) if r and r.client_id == c1.client_id]
    assert len(runs) == 2
    assert runs[0].audit_run_id != runs[1].audit_run_id
    assert all(looks_like_audit_run_id(r.audit_run_id) for r in runs)
    assert all(r.client_id == c1.client_id for r in runs)


def _list_runs(registry):
    with registry._lock:
        with registry._connect() as conn:
            rows = conn.execute(
                "SELECT audit_run_id FROM audit_runs ORDER BY created_at"
            ).fetchall()
    return [registry.get_run(str(r["audit_run_id"])) for r in rows]


@pytest.mark.asyncio
async def test_resume_preserves_audit_run_id(tmp_path: Path):
    """Resume / continue keeps the same audit_run_id (no new run)."""
    settings = _settings(tmp_path)
    client = get_client_registry(tmp_path).ensure_client(
        display_name="Beta", slug="beta"
    )
    registry = get_audit_registry(tmp_path)
    arun = registry.create_run(
        client_id=client.client_id,
        evidence_run_id=f"beta/{new_audit_run_id()}",
        base_thread_id="t-resume",
    )
    # Align evidence path with audit_run_id
    evidence_key = f"beta/{arun.audit_run_id}"
    arun.evidence_run_id = evidence_key
    registry.save_run(arun)
    registry.mark_run_started(arun.audit_run_id)
    store = EvidenceStore(tmp_path, run_id=evidence_key)
    store.write_run_meta(
        client_id=client.client_id,
        client_slug="beta",
        audit_run_id=arun.audit_run_id,
        thread_id="t-resume",
        continue_thread_id="t-resume",
        status="interrupted",
    )
    registry.transition_run(arun.audit_run_id, AuditRunStatus.CANCELLED)
    registry.resume_run(arun.audit_run_id)
    again = registry.get_run(arun.audit_run_id)
    assert again is not None
    assert again.audit_run_id == arun.audit_run_id
    assert again.client_id == client.client_id
    assert again.status.value == "running"


def test_write_finding_rejects_missing_audit_run_id(tmp_path: Path):
    store = EvidenceStore(tmp_path, run_id="tmp")
    with pytest.raises(MissingAuditRunIdError):
        store.write_finding(
            "fw",
            "REQ-001",
            {"status": "fail", "client_id": "client_abc1234567890"},
        )
    with pytest.raises(MissingAuditRunIdError):
        store.write_finding(
            "fw",
            "REQ-001",
            {
                "status": "fail",
                "client_id": "client_abc1234567890",
                "audit_run_id": "acme_corp",  # slug, not arun_
            },
        )


def test_results_isolated_across_runs(tmp_path: Path):
    """Findings for two runs of the same client stay in separate folders."""
    client = get_client_registry(tmp_path).ensure_client(
        display_name="Gamma", slug="gamma"
    )
    registry = get_audit_registry(tmp_path)
    a = registry.create_run(client_id=client.client_id)
    b = registry.create_run(client_id=client.client_id)
    registry.mark_run_started(a.audit_run_id)
    registry.mark_run_started(b.audit_run_id)
    sa = EvidenceStore(tmp_path, run_id=f"gamma/{a.audit_run_id}")
    sb = EvidenceStore(tmp_path, run_id=f"gamma/{b.audit_run_id}")
    sa.write_run_meta(client_id=client.client_id, audit_run_id=a.audit_run_id)
    sb.write_run_meta(client_id=client.client_id, audit_run_id=b.audit_run_id)
    payload_a = {
        "status": "pass",
        "client_id": client.client_id,
        "audit_run_id": a.audit_run_id,
        "requirement_id": "REQ-001",
    }
    payload_b = {
        "status": "fail",
        "client_id": client.client_id,
        "audit_run_id": b.audit_run_id,
        "requirement_id": "REQ-001",
    }
    sa.write_finding("fw1", "REQ-001", payload_a)
    sb.write_finding("fw1", "REQ-001", payload_b)
    fa = sa.load_findings("fw1")
    fb = sb.load_findings("fw1")
    assert next(iter(fa.values()))["status"] == "pass"
    assert next(iter(fb.values()))["status"] == "fail"
    assert next(iter(fa.values()))["audit_run_id"] != next(iter(fb.values()))["audit_run_id"]
    assert sa.root != sb.root


@pytest.mark.asyncio
async def test_concurrent_runs_cannot_cross_read_jobs(tmp_path: Path):
    """Jobs for run A are not visible under run B's registry listing."""
    client = get_client_registry(tmp_path).ensure_client(
        display_name="Delta", slug="delta"
    )
    registry = get_audit_registry(tmp_path)
    a = registry.create_run(client_id=client.client_id)
    b = registry.create_run(client_id=client.client_id)
    registry.mark_run_started(a.audit_run_id)
    registry.mark_run_started(b.audit_run_id)
    from auditor.domain import AuditJobType

    ja = registry.create_job(
        audit_run_id=a.audit_run_id,
        logical_task_id="h1/fw1",
        job_type=AuditJobType.ASSESS_FRAMEWORK,
    )
    jb = registry.create_job(
        audit_run_id=b.audit_run_id,
        logical_task_id="h1/fw1",
        job_type=AuditJobType.ASSESS_FRAMEWORK,
    )
    assert ja.job_id != jb.job_id
    jobs_a = registry.list_jobs(a.audit_run_id)
    jobs_b = registry.list_jobs(b.audit_run_id)
    assert [j.job_id for j in jobs_a] == [ja.job_id]
    assert [j.job_id for j in jobs_b] == [jb.job_id]

    # Concurrent evidence writes stay isolated.
    def _write(store: EvidenceStore, arun: str, status: str) -> None:
        store.write_finding(
            "fw1",
            "REQ-001",
            {
                "status": status,
                "client_id": client.client_id,
                "audit_run_id": arun,
            },
        )

    sa = EvidenceStore(tmp_path, run_id=f"delta/{a.audit_run_id}")
    sb = EvidenceStore(tmp_path, run_id=f"delta/{b.audit_run_id}")
    await asyncio.gather(
        asyncio.to_thread(_write, sa, a.audit_run_id, "pass"),
        asyncio.to_thread(_write, sb, b.audit_run_id, "fail"),
    )
    fa = sa.load_findings("fw1")
    fb = sb.load_findings("fw1")
    assert next(iter(fa.values()))["status"] == "pass"
    assert next(iter(fb.values()))["status"] == "fail"


def test_client_name_or_slug_rejected_as_audit_run_id():
    with pytest.raises(MissingAuditRunIdError):
        require_audit_run_id("AcmeCorp", context="test")
    with pytest.raises(MissingAuditRunIdError):
        require_audit_run_id("acme_corp", context="test")
    with pytest.raises(MissingAuditRunIdError):
        require_audit_run_id("", context="test")
    ok = require_audit_run_id("arun_deadbeefcafebabe", context="test")
    assert ok == "arun_deadbeefcafebabe"


def test_legacy_compat_reports_ambiguous_without_guessing(tmp_path: Path):
    """Legacy flat folders without audit_run_id are reported, not guessed."""
    legacy = tmp_path / "OldClient"
    legacy.mkdir()
    (legacy / "meta.json").write_text(
        '{"client_name":"OldClient","status":"completed"}',
        encoding="utf-8",
    )
    reported = report_legacy_without_audit_run(tmp_path, client_slug="OldClient")
    assert len(reported) == 1
    assert reported[0].legacy is True
    assert not reported[0].audit_run_id

    # Two nested runs for same client → ambiguous resolve by slug alone.
    slug = tmp_path / "twin"
    (slug / "arun_aaaaaaaaaaaaaaaa").mkdir(parents=True)
    (slug / "arun_bbbbbbbbbbbbbbbb").mkdir(parents=True)
    (slug / "arun_aaaaaaaaaaaaaaaa" / "meta.json").write_text(
        '{"audit_run_id":"arun_aaaaaaaaaaaaaaaa"}', encoding="utf-8"
    )
    (slug / "arun_bbbbbbbbbbbbbbbb" / "meta.json").write_text(
        '{"audit_run_id":"arun_bbbbbbbbbbbbbbbb"}', encoding="utf-8"
    )
    with pytest.raises(AmbiguousLegacyRunError):
        EvidenceStore.open_existing(tmp_path, "twin")

    hit = resolve_evidence_for_audit_run(tmp_path, "arun_aaaaaaaaaaaaaaaa")
    assert hit.evidence_run_id == "twin/arun_aaaaaaaaaaaaaaaa"


@pytest.mark.asyncio
async def test_arun_one_reuses_client_and_preserves_run_on_resume_path(
    tmp_path: Path,
):
    """arun_one allocates durable client_id; second call with same audit_run_id keeps it."""
    settings = _settings(tmp_path)
    graph = AuditorGraph(settings=settings)

    async def fake_invoke(initial, config):
        del config
        return {
            **initial,
            "report": "done",
            "awaiting_hitl": False,
            "messages": [],
        }

    with patch.object(graph.graph, "ainvoke", side_effect=fake_invoke):
        first = await graph.arun_one(
            "audit",
            framework_id="fw1",
            intake_state={"client_name": "Zeta", "intake_complete": True},
        )
    cid = first.get("client_id") or ""
    arid = first.get("audit_run_id") or ""
    # State may be nested; fall back to registry / meta
    registry = get_audit_registry(tmp_path)
    runs = _list_runs(registry)
    assert len(runs) == 1
    assert runs[0].client_id.startswith("client_")
    assert looks_like_audit_run_id(runs[0].audit_run_id)

    with patch.object(graph.graph, "ainvoke", side_effect=fake_invoke):
        second = await graph.arun_one(
            "audit again",
            framework_id="fw1",
            intake_state={
                "client_name": "Zeta",
                "client_id": runs[0].client_id,
                "audit_run_id": runs[0].audit_run_id,
                "intake_complete": True,
            },
            run_id=runs[0].evidence_run_id or None,
        )
    runs2 = _list_runs(registry)
    assert len(runs2) == 1
    assert runs2[0].audit_run_id == runs[0].audit_run_id
    assert runs2[0].client_id == runs[0].client_id
    del cid, arid, second

"""CORE-001: Separate persistent client_id from audit_run_id."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from tests.fixtures.canonical_audit import (
    CLIENT_ALPHA_ID,
    CLIENT_BETA_ID,
    RUN_ALPHA_CURRENT_ID,
    RUN_ALPHA_PREVIOUS_ID,
    RUN_BETA_CURRENT_ID,
    build_canonical_scenario,
)
from tests.helpers.audit_request import intake_with_request

from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry, looks_like_audit_run_id
from auditor.config import Settings
from auditor.domain import AuditRunStatus, new_audit_run_id
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph
from auditor.legacy_compat import (
    AmbiguousLegacyRunError,
    ClientOwnershipError,
    MissingAuditRunIdError,
    MissingClientIdError,
    report_legacy_without_audit_run,
    require_audit_run_id,
    require_client_id,
    resolve_evidence_for_audit_run,
)
from auditor.secrets_file import InventorySshTarget
from auditor.state import Finding


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
                intake_state=intake_with_request(
                    c1.client_id,
                    client_name="Acme Corp",
                    client_slug="acme_corp",
                    host="h1",
                    framework_id="fw1",
                ),
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
    _settings(tmp_path)
    client = get_client_registry(tmp_path).ensure_client(display_name="Beta", slug="beta")
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
    client = get_client_registry(tmp_path).ensure_client(display_name="Gamma", slug="gamma")
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
        "result_id": "11111111-1111-4111-8111-111111111111",
        "asset_id": "aaaaaaaa-1111-4111-8111-111111111111",
        "framework_id": "fw1",
        "framework_version": "1.0.0",
        "observation": "pass observation",
    }
    payload_b = {
        "status": "fail",
        "client_id": client.client_id,
        "audit_run_id": b.audit_run_id,
        "requirement_id": "REQ-001",
        "result_id": "22222222-2222-4222-8222-222222222222",
        "asset_id": "aaaaaaaa-1111-4111-8111-111111111111",
        "framework_id": "fw1",
        "framework_version": "1.0.0",
        "observation": "fail observation",
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
    client = get_client_registry(tmp_path).ensure_client(display_name="Delta", slug="delta")
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
                "requirement_id": "REQ-001",
                "result_id": "33333333-3333-4333-8333-333333333333"
                if status == "pass"
                else "44444444-4444-4444-8444-444444444444",
                "asset_id": "aaaaaaaa-1111-4111-8111-111111111111",
                "framework_id": "fw1",
                "framework_version": "1.0.0",
                "observation": status,
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


def test_require_client_id_rejects_empty_and_audit_run_values():
    with pytest.raises(MissingClientIdError):
        require_client_id(None, context="test")
    with pytest.raises(MissingClientIdError):
        require_client_id("", context="test")
    with pytest.raises(MissingClientIdError):
        require_client_id("   ", context="test")
    with pytest.raises(MissingClientIdError):
        require_client_id(RUN_ALPHA_CURRENT_ID, context="test")
    assert require_client_id(CLIENT_ALPHA_ID) == CLIENT_ALPHA_ID


def test_canonical_two_runs_same_client_and_independent_beta(tmp_path: Path):
    """AUD-003 fixtures: alpha has two runs; beta has an independent run."""
    scenario = build_canonical_scenario()
    registry = get_audit_registry(tmp_path)
    alpha = next(c for c in scenario.clients if c.client_id == CLIENT_ALPHA_ID)
    beta = next(c for c in scenario.clients if c.client_id == CLIENT_BETA_ID)
    get_client_registry(tmp_path).ensure_client(
        display_name=alpha.display_name, slug=alpha.slug, client_id=alpha.client_id
    )
    get_client_registry(tmp_path).ensure_client(
        display_name=beta.display_name, slug=beta.slug, client_id=beta.client_id
    )
    prev = registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID)
    curr = registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    other = registry.create_run(client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID)
    assert prev.client_id == curr.client_id == CLIENT_ALPHA_ID
    assert prev.audit_run_id != curr.audit_run_id
    assert other.client_id == CLIENT_BETA_ID
    assert other.audit_run_id == RUN_BETA_CURRENT_ID
    assert {r.audit_run_id for r in _list_runs(registry)} == {
        RUN_ALPHA_PREVIOUS_ID,
        RUN_ALPHA_CURRENT_ID,
        RUN_BETA_CURRENT_ID,
    }


def test_create_run_rejects_empty_client_id(tmp_path: Path):
    registry = get_audit_registry(tmp_path)
    with pytest.raises(MissingClientIdError):
        registry.create_run(client_id="")
    with pytest.raises(MissingClientIdError):
        registry.create_run(client_id="   ")


def test_cannot_reassign_audit_run_to_another_client(tmp_path: Path):
    scenario = build_canonical_scenario()
    registry = get_audit_registry(tmp_path)
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha", slug="client_alpha", client_id=CLIENT_ALPHA_ID
    )
    get_client_registry(tmp_path).ensure_client(
        display_name="Beta", slug="client_beta", client_id=CLIENT_BETA_ID
    )
    run = registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    run.client_id = CLIENT_BETA_ID
    with pytest.raises(ClientOwnershipError):
        registry.save_run(run)
    again = registry.get_run(RUN_ALPHA_CURRENT_ID)
    assert again is not None
    assert again.client_id == CLIENT_ALPHA_ID
    del scenario


def test_write_finding_rejects_missing_client_id(tmp_path: Path):
    store = EvidenceStore(tmp_path, run_id="tmp")
    with pytest.raises(MissingClientIdError):
        store.write_finding(
            "fw",
            "REQ-001",
            {"status": "fail", "audit_run_id": RUN_ALPHA_CURRENT_ID, "client_id": ""},
        )


def test_serialization_round_trip_preserves_both_ids():
    scenario = build_canonical_scenario()
    finding = scenario.result_by_status("fail")
    payload = finding.model_dump()
    assert payload["client_id"] == CLIENT_ALPHA_ID
    assert payload["audit_run_id"] == RUN_ALPHA_CURRENT_ID
    restored = Finding(**payload)
    assert restored.client_id == finding.client_id
    assert restored.audit_run_id == finding.audit_run_id
    assert restored.client_id != restored.audit_run_id

    run = scenario.audit_runs[1]
    data = run.to_dict()
    assert data["client_id"] == CLIENT_ALPHA_ID
    assert data["audit_run_id"] == RUN_ALPHA_CURRENT_ID
    # evidence_run_id is a path key, not a silent copy of either identity
    assert "evidence_run_id" in data
    assert data["evidence_run_id"] != data["client_id"]
    roundtrip = type(run).from_dict(data)
    assert roundtrip.client_id == run.client_id
    assert roundtrip.audit_run_id == run.audit_run_id


def test_evidence_insert_update_targets_exact_run(tmp_path: Path):
    scenario = build_canonical_scenario()
    registry = get_audit_registry(tmp_path)
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha", slug="client_alpha", client_id=CLIENT_ALPHA_ID
    )
    registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID)
    registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    sa = EvidenceStore(tmp_path, run_id=f"client_alpha/{RUN_ALPHA_PREVIOUS_ID}")
    sb = EvidenceStore(tmp_path, run_id=f"client_alpha/{RUN_ALPHA_CURRENT_ID}")
    sa.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID)
    sb.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    base = scenario.result_by_status("fail")
    sa.write_finding(
        "framework_linux",
        "REQ-001",
        {
            "status": "fail",
            "client_id": CLIENT_ALPHA_ID,
            "audit_run_id": RUN_ALPHA_PREVIOUS_ID,
            "result_id": scenario.previous_comparable_result.result_id,
            "asset_id": scenario.previous_comparable_result.asset_id,
            "framework_id": "framework_linux",
            "framework_version": "1.0.0",
            "requirement_id": "REQ-001",
            "observation": "previous fail",
        },
    )
    sb.write_finding(
        "framework_linux",
        "REQ-001",
        {
            "status": "accepted_exception",
            "client_id": CLIENT_ALPHA_ID,
            "audit_run_id": RUN_ALPHA_CURRENT_ID,
            "result_id": base.result_id,
            "asset_id": base.asset_id,
            "framework_id": "framework_linux",
            "framework_version": "1.0.0",
            "requirement_id": "REQ-001",
            "observation": "exception",
        },
    )
    # update current run only
    sb.write_finding(
        "framework_linux",
        "REQ-001",
        {
            "status": "pass",
            "client_id": CLIENT_ALPHA_ID,
            "audit_run_id": RUN_ALPHA_CURRENT_ID,
            "result_id": base.result_id,
            "asset_id": base.asset_id,
            "framework_id": "framework_linux",
            "framework_version": "1.0.0",
            "requirement_id": "REQ-001",
            "observation": "fixed",
        },
    )
    assert next(iter(sa.load_findings("framework_linux").values()))["status"] == "fail"
    assert next(iter(sb.load_findings("framework_linux").values()))["status"] == "pass"
    assert (
        next(iter(sa.load_findings("framework_linux").values()))["audit_run_id"]
        == RUN_ALPHA_PREVIOUS_ID
    )


@pytest.mark.asyncio
async def test_arun_one_rejects_conflicting_client_ownership(tmp_path: Path):
    settings = _settings(tmp_path)
    graph = AuditorGraph(settings=settings)
    clients = get_client_registry(tmp_path)
    alpha = clients.ensure_client(
        display_name="Alpha", slug="client_alpha", client_id=CLIENT_ALPHA_ID
    )
    beta = clients.ensure_client(display_name="Beta", slug="client_beta", client_id=CLIENT_BETA_ID)
    registry = get_audit_registry(tmp_path)
    registry.create_run(
        client_id=alpha.client_id,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        evidence_run_id=f"client_alpha/{RUN_ALPHA_CURRENT_ID}",
    )

    async def fake_invoke(initial, config):
        del config
        return {**initial, "report": "done", "awaiting_hitl": False, "messages": []}

    with patch.object(graph.graph, "ainvoke", side_effect=fake_invoke):
        with pytest.raises(ClientOwnershipError):
            await graph.arun_one(
                "audit",
                framework_id="fw1",
                intake_state={
                    "client_name": "Beta",
                    "client_slug": "client_beta",
                    "client_id": beta.client_id,
                    "audit_run_id": RUN_ALPHA_CURRENT_ID,
                    "intake_complete": True,
                },
            )


def test_resume_exact_run_preserves_client_from_canonical(tmp_path: Path):
    """Resume keeps the exact audit_run_id and stored client_id (AUD-003 ids)."""
    _settings(tmp_path)
    clients = get_client_registry(tmp_path)
    alpha = clients.ensure_client(
        display_name="Alpha", slug="client_alpha", client_id=CLIENT_ALPHA_ID
    )
    registry = get_audit_registry(tmp_path)
    evidence_key = f"client_alpha/{RUN_ALPHA_CURRENT_ID}"
    registry.create_run(
        client_id=alpha.client_id,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        evidence_run_id=evidence_key,
        base_thread_id="t-core001",
    )
    registry.mark_run_started(RUN_ALPHA_CURRENT_ID)
    store = EvidenceStore(tmp_path, run_id=evidence_key)
    store.write_run_meta(
        client_id=alpha.client_id,
        client_slug="client_alpha",
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        thread_id="t-core001",
        status="interrupted",
    )
    registry.transition_run(RUN_ALPHA_CURRENT_ID, AuditRunStatus.CANCELLED)
    resumed = registry.resume_run(RUN_ALPHA_CURRENT_ID)
    assert resumed.audit_run_id == RUN_ALPHA_CURRENT_ID
    assert resumed.client_id == CLIENT_ALPHA_ID
    # Must not pick beta's run
    registry.create_run(
        client_id=CLIENT_BETA_ID,
        audit_run_id=RUN_BETA_CURRENT_ID,
        evidence_run_id=f"client_beta/{RUN_BETA_CURRENT_ID}",
    )
    again = registry.get_run(RUN_ALPHA_CURRENT_ID)
    assert again is not None
    assert again.audit_run_id != RUN_BETA_CURRENT_ID
    assert again.client_id == CLIENT_ALPHA_ID


def test_req001_separated_across_assets_and_frameworks():
    scenario = build_canonical_scenario()
    from auditor.domain.result_identity import logical_key_of

    keys = set()
    for finding in scenario.results:
        if finding.requirement_id != "REQ-001":
            continue
        if finding.audit_run_id != RUN_ALPHA_CURRENT_ID:
            continue
        keys.add(logical_key_of(finding).as_tuple())
    # At least two distinct logical keys under same REQ-001 (asset and/or framework)
    assert len(keys) >= 2
    # Previous comparable vs non-comparable prove framework scope
    assert (
        scenario.previous_comparable_result.framework_id
        != scenario.previous_noncomparable_result.framework_id
    )
    assert (
        scenario.previous_comparable_result.requirement_id
        == scenario.previous_noncomparable_result.requirement_id
        == "REQ-001"
    )


def test_legacy_run_id_means_evidence_folder_not_audit_run(tmp_path: Path):
    """API ``run_id`` / evidence_run_id is a path key; audit_run_id stays separate."""
    store = EvidenceStore(tmp_path, run_id=f"client_alpha/{RUN_ALPHA_CURRENT_ID}")
    assert store.run_id == f"client_alpha/{RUN_ALPHA_CURRENT_ID}"
    store.write_run_meta(
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    meta = store.read_run_meta()
    assert meta["client_id"] == CLIENT_ALPHA_ID
    assert meta["audit_run_id"] == RUN_ALPHA_CURRENT_ID
    assert meta["audit_run_id"] != store.run_id or store.run_id.endswith(RUN_ALPHA_CURRENT_ID)
    # evidence folder id must not validate as the business audit_run_id alone when nested
    with pytest.raises(MissingAuditRunIdError):
        require_audit_run_id(store.run_id, context="legacy-check")


def test_create_run_rejects_client_id_as_audit_run_id(tmp_path: Path):
    """Explicit audit_run_id must be arun_*; client_* values are rejected."""
    registry = get_audit_registry(tmp_path)
    with pytest.raises(MissingAuditRunIdError):
        registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=CLIENT_ALPHA_ID)
    with pytest.raises(MissingAuditRunIdError):
        registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id="client_swapped00001")


def test_save_run_rejects_invalid_or_swapped_audit_run_id(tmp_path: Path):
    registry = get_audit_registry(tmp_path)
    run = registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    run.audit_run_id = CLIENT_ALPHA_ID
    with pytest.raises(MissingAuditRunIdError):
        registry.save_run(run)
    run.audit_run_id = ""
    with pytest.raises(MissingAuditRunIdError):
        registry.save_run(run)
    run.audit_run_id = "acme_corp"
    with pytest.raises(MissingAuditRunIdError):
        registry.save_run(run)
    # Original row must remain under the valid id.
    again = registry.get_run(RUN_ALPHA_CURRENT_ID)
    assert again is not None
    assert again.client_id == CLIENT_ALPHA_ID
    assert again.audit_run_id == RUN_ALPHA_CURRENT_ID


def test_create_and_save_run_accept_generated_and_explicit_arun_ids(tmp_path: Path):
    registry = get_audit_registry(tmp_path)
    generated = registry.create_run(client_id=CLIENT_ALPHA_ID)
    assert looks_like_audit_run_id(generated.audit_run_id)
    generated.evidence_run_id = f"client_alpha/{generated.audit_run_id}"
    registry.save_run(generated)
    stored = registry.get_run(generated.audit_run_id)
    assert stored is not None
    assert stored.evidence_run_id == generated.evidence_run_id

    explicit = registry.create_run(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID)
    assert explicit.audit_run_id == RUN_ALPHA_PREVIOUS_ID
    explicit.base_thread_id = "t-core001-gap"
    registry.save_run(explicit)
    again = registry.get_run(RUN_ALPHA_PREVIOUS_ID)
    assert again is not None
    assert again.base_thread_id == "t-core001-gap"

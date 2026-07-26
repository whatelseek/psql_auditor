"""CORE-005 — checkpoint and artifact isolation by audit run."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.fixtures.canonical_audit import (
    ASSET_LINUX_01_ID,
    CLIENT_ALPHA_ID,
    CLIENT_BETA_ID,
    FRAMEWORK_LINUX_ID,
    FRAMEWORK_VERSION,
    RUN_ALPHA_CURRENT_ID,
    RUN_ALPHA_PREVIOUS_ID,
    RUN_BETA_CURRENT_ID,
    build_canonical_scenario,
)

from auditor.audit_registry import get_audit_registry
from auditor.checklist import Requirement
from auditor.client_registry import get_client_registry
from auditor.config import Settings
from auditor.domain.assessment_result import AssessmentResult
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph
from auditor.legacy_compat import ClientOwnershipError
from auditor.run_scope import (
    OwnershipManifest,
    OwnershipManifestError,
    RunScopeIsolationError,
    assert_thread_belongs_to_run,
    checkpoint_thread_id,
    cleanup_run_scope,
    open_run_scope,
    read_ownership_manifest,
    resolve_run_scope,
    resolve_under_run_root,
    write_ownership_manifest,
)
from auditor.state import Finding, render_report


def test_checkpoint_scopes_differ_across_runs_and_clients():
    a1 = checkpoint_thread_id(CLIENT_ALPHA_ID, RUN_ALPHA_PREVIOUS_ID)
    a2 = checkpoint_thread_id(CLIENT_ALPHA_ID, RUN_ALPHA_CURRENT_ID)
    b1 = checkpoint_thread_id(CLIENT_BETA_ID, RUN_BETA_CURRENT_ID)
    assert a1 != a2
    assert a1 != b1
    assert a1.startswith("audit:")
    assert CLIENT_ALPHA_ID in a1 and RUN_ALPHA_PREVIOUS_ID in a1
    # Resume of the same run is deterministic.
    assert checkpoint_thread_id(CLIENT_ALPHA_ID, RUN_ALPHA_CURRENT_ID) == a2
    assert_thread_belongs_to_run(
        f"{a2}:framework_linux",
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    with pytest.raises(RunScopeIsolationError):
        assert_thread_belongs_to_run(
            a1,
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
        )


def test_swapped_client_and_run_ids_rejected():
    with pytest.raises(Exception):
        checkpoint_thread_id(RUN_ALPHA_CURRENT_ID, CLIENT_ALPHA_ID)


def test_artifact_roots_and_ownership_manifest(tmp_path: Path):
    scope_a = resolve_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        client_slug="client_alpha",
    )
    scope_b = resolve_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        client_slug="client_alpha",
    )
    assert scope_a.artifact_root != scope_b.artifact_root
    assert scope_a.checkpoint_db_path != scope_b.checkpoint_db_path
    open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        client_slug="client_alpha",
        create=True,
    )
    open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        client_slug="client_alpha",
        create=True,
    )
    own = read_ownership_manifest(scope_a.artifact_root)
    assert own.client_id == CLIENT_ALPHA_ID
    assert own.audit_run_id == RUN_ALPHA_PREVIOUS_ID
    with pytest.raises(OwnershipManifestError):
        write_ownership_manifest(
            scope_a.artifact_root,
            OwnershipManifest(client_id=CLIENT_BETA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID),
        )


def test_ownership_missing_and_malformed_fail_closed(tmp_path: Path):
    root = tmp_path / "client_alpha" / RUN_ALPHA_CURRENT_ID
    root.mkdir(parents=True)
    with pytest.raises(OwnershipManifestError):
        read_ownership_manifest(root)
    (root / "ownership.json").write_text("{not-json", encoding="utf-8")
    with pytest.raises(OwnershipManifestError):
        read_ownership_manifest(root)


def test_path_traversal_rejected(tmp_path: Path):
    scope = open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        client_slug="client_alpha",
        create=True,
    )
    with pytest.raises(RunScopeIsolationError):
        resolve_under_run_root(scope.artifact_root, "../escape.txt")
    with pytest.raises(RunScopeIsolationError):
        resolve_under_run_root(scope.artifact_root, "/etc/passwd")
    with pytest.raises(RunScopeIsolationError):
        resolve_under_run_root(scope.artifact_root, "ownership.json")


def test_identical_req001_artifacts_are_isolated(tmp_path: Path):
    scenario = build_canonical_scenario()
    prev = AssessmentResult.from_finding(scenario.result_by_status("pass"))
    # Force same requirement id content into two run scopes.
    sa = open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        client_slug="client_alpha",
        create=True,
    )
    sb = open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        client_slug="client_alpha",
        create=True,
    )
    store_a = EvidenceStore(tmp_path, run_id=sa.evidence_run_id)
    store_b = EvidenceStore(tmp_path, run_id=sb.evidence_run_id)
    store_a.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID)
    store_b.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    payload = prev.to_persist_dict()
    payload["requirement_id"] = "REQ-001"
    payload["observation"] = "prev-run"
    store_a.write_finding(FRAMEWORK_LINUX_ID, "REQ-001", payload)
    payload_b = dict(payload)
    payload_b["observation"] = "curr-run"
    payload_b["audit_run_id"] = RUN_ALPHA_CURRENT_ID
    payload_b["result_id"] = "a0000001-0001-4001-8001-000000000099"
    store_b.write_finding(FRAMEWORK_LINUX_ID, "REQ-001", payload_b)
    assert store_a.load_finding(FRAMEWORK_LINUX_ID, "REQ-001")["observation"] == "prev-run"
    assert store_b.load_finding(FRAMEWORK_LINUX_ID, "REQ-001")["observation"] == "curr-run"
    # Same filename under different roots.
    (sa.artifact_root / "report.md").write_text("A", encoding="utf-8")
    (sb.artifact_root / "report.md").write_text("B", encoding="utf-8")
    assert (sa.artifact_root / "report.md").read_text(encoding="utf-8") == "A"
    assert (sb.artifact_root / "report.md").read_text(encoding="utf-8") == "B"


def test_cleanup_one_run_leaves_other(tmp_path: Path):
    sa = open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        client_slug="client_alpha",
        create=True,
    )
    sb = open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        client_slug="client_alpha",
        create=True,
    )
    sa.checkpoint_db_path.parent.mkdir(parents=True, exist_ok=True)
    sa.checkpoint_db_path.write_text("ckpt-a", encoding="utf-8")
    sb.checkpoint_db_path.parent.mkdir(parents=True, exist_ok=True)
    sb.checkpoint_db_path.write_text("ckpt-b", encoding="utf-8")
    (sa.artifact_root / "keep.txt").write_text("x", encoding="utf-8")
    (sb.artifact_root / "keep.txt").write_text("y", encoding="utf-8")
    cleanup_run_scope(sa)
    assert not sa.artifact_root.exists()
    assert not sa.checkpoint_db_path.exists()
    assert sb.artifact_root.is_dir()
    assert sb.checkpoint_db_path.read_text(encoding="utf-8") == "ckpt-b"


def test_legacy_flat_folder_not_silently_adopted(tmp_path: Path):
    legacy = tmp_path / "AlphaCo"
    legacy.mkdir()
    (legacy / "meta.json").write_text("{}", encoding="utf-8")
    with pytest.raises(OwnershipManifestError):
        EvidenceStore.open_existing(
            tmp_path,
            "AlphaCo",
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
        )


@pytest.mark.asyncio
async def test_arun_one_isolates_checkpoints_and_artifacts(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        checkpoint_path=tmp_path / "legacy.sqlite",
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
        max_parallel_assessments=1,
    )
    graph = AuditorGraph(settings=settings)
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha",
        slug="client_alpha",
        client_id=CLIENT_ALPHA_ID,
    )
    reg = get_audit_registry(tmp_path)
    reg.create_run(
        client_id=CLIENT_ALPHA_ID,
        scope={"client_slug": "client_alpha"},
        evidence_run_id="",
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
    )
    reg.create_run(
        client_id=CLIENT_ALPHA_ID,
        scope={"client_slug": "client_alpha"},
        evidence_run_id="",
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )

    async def fake_fill(req_id, requirement, user_request, framework_id="", store=None, **_kw):
        return Finding(
            requirement_id=req_id,
            title=requirement.title,
            status="pass",
            evidence="ok",
        )

    {"REQ-001": Requirement(id="REQ-001", title="A")}
    with patch.object(graph, "_fill_requirement_cells", side_effect=fake_fill):
        with patch.object(
            graph,
            "assess_parallel",
            side_effect=lambda state: {
                "findings": {
                    "r1": AssessmentResult.from_finding(
                        Finding(
                            requirement_id="REQ-001",
                            status="pass",
                            evidence="a",
                            result_id="a0000001-0001-4001-8001-000000000021",
                            client_id=CLIENT_ALPHA_ID,
                            audit_run_id=str(state.get("audit_run_id") or ""),
                            asset_id=ASSET_LINUX_01_ID,
                            framework_id=FRAMEWORK_LINUX_ID,
                            framework_version=FRAMEWORK_VERSION,
                        )
                    )
                },
                "pending_ids": [],
            },
        ):
            # Patch whole graph invoke to avoid full checklist load for missing agent.
            async def fake_ainvoke(initial, config):
                return {
                    **initial,
                    "findings": {},
                    "pending_ids": [],
                    "report": "ok",
                }

            with patch.object(graph.graph, "ainvoke", side_effect=fake_ainvoke):
                r1 = await graph.arun_one(
                    "audit previous",
                    framework_id=FRAMEWORK_LINUX_ID,
                    intake_state={
                        "client_id": CLIENT_ALPHA_ID,
                        "client_slug": "client_alpha",
                        "client_name": "Alpha",
                        "audit_run_id": RUN_ALPHA_PREVIOUS_ID,
                        "asset_id": ASSET_LINUX_01_ID,
                        "framework_version": FRAMEWORK_VERSION,
                        "intake": {"client_name": "Alpha"},
                    },
                )
                r2 = await graph.arun_one(
                    "audit current",
                    framework_id=FRAMEWORK_LINUX_ID,
                    intake_state={
                        "client_id": CLIENT_ALPHA_ID,
                        "client_slug": "client_alpha",
                        "client_name": "Alpha",
                        "audit_run_id": RUN_ALPHA_CURRENT_ID,
                        "asset_id": ASSET_LINUX_01_ID,
                        "framework_version": FRAMEWORK_VERSION,
                        "intake": {"client_name": "Alpha"},
                    },
                )

    tid1 = str(r1.get("thread_id") or "")
    tid2 = str(r2.get("thread_id") or "")
    assert tid1 != tid2
    assert tid1.startswith(f"audit:{CLIENT_ALPHA_ID}:{RUN_ALPHA_PREVIOUS_ID}")
    assert tid2.startswith(f"audit:{CLIENT_ALPHA_ID}:{RUN_ALPHA_CURRENT_ID}")
    scope1 = resolve_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        client_slug="client_alpha",
    )
    scope2 = resolve_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        client_slug="client_alpha",
    )
    assert scope1.artifact_root.is_dir()
    assert scope2.artifact_root.is_dir()
    assert (scope1.artifact_root / "ownership.json").is_file()
    assert (scope2.artifact_root / "ownership.json").is_file()
    assert scope1.checkpoint_db_path != scope2.checkpoint_db_path


@pytest.mark.asyncio
async def test_foreign_thread_cannot_bypass_isolation(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
    )
    graph = AuditorGraph(settings=settings)
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha", slug="client_alpha", client_id=CLIENT_ALPHA_ID
    )
    get_audit_registry(tmp_path).create_run(
        client_id=CLIENT_ALPHA_ID,
        scope={"client_slug": "client_alpha"},
        evidence_run_id="",
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        base_thread_id=checkpoint_thread_id(CLIENT_ALPHA_ID, RUN_ALPHA_CURRENT_ID),
    )
    open_run_scope(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        client_slug="client_alpha",
        create=True,
    )
    with pytest.raises(RunScopeIsolationError):
        await graph.aresume(
            f"audit:{CLIENT_BETA_ID}:{RUN_BETA_CURRENT_ID}",
            "continue",
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
        )


@pytest.mark.asyncio
async def test_cross_client_and_cross_run_resume_rejected(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
    )
    graph = AuditorGraph(settings=settings)
    reg = get_audit_registry(tmp_path)
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha", slug="client_alpha", client_id=CLIENT_ALPHA_ID
    )
    get_client_registry(tmp_path).ensure_client(
        display_name="Beta", slug="client_beta", client_id=CLIENT_BETA_ID
    )
    reg.create_run(
        client_id=CLIENT_ALPHA_ID,
        scope={},
        evidence_run_id="",
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    reg.create_run(
        client_id=CLIENT_BETA_ID,
        scope={},
        evidence_run_id="",
        audit_run_id=RUN_BETA_CURRENT_ID,
    )
    tid = checkpoint_thread_id(CLIENT_ALPHA_ID, RUN_ALPHA_CURRENT_ID)
    with pytest.raises((RunScopeIsolationError, ClientOwnershipError)):
        await graph.aresume(
            tid,
            "continue",
            client_id=CLIENT_BETA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
        )
    with pytest.raises(RunScopeIsolationError):
        await graph.aresume(
            tid,
            "continue",
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        )


@pytest.mark.asyncio
async def test_concurrent_runs_do_not_mix_artifacts(tmp_path: Path):
    async def _one(arid: str, mark: str) -> str:
        scope = open_run_scope(
            tmp_path,
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=arid,
            client_slug="client_alpha",
            create=True,
        )
        path = scope.artifact_root / "marker.txt"
        path.write_text(mark, encoding="utf-8")
        await asyncio.sleep(0.01)
        return path.read_text(encoding="utf-8")

    out = await asyncio.gather(
        _one(RUN_ALPHA_PREVIOUS_ID, "prev"),
        _one(RUN_ALPHA_CURRENT_ID, "curr"),
    )
    assert set(out) == {"prev", "curr"}
    assert (tmp_path / "client_alpha" / RUN_ALPHA_PREVIOUS_ID / "marker.txt").read_text(
        encoding="utf-8"
    ) == "prev"
    assert (tmp_path / "client_alpha" / RUN_ALPHA_CURRENT_ID / "marker.txt").read_text(
        encoding="utf-8"
    ) == "curr"


def test_report_generation_compatible_with_scoped_results():
    scenario = build_canonical_scenario()
    sample = AssessmentResult.from_finding(scenario.result_by_status("fail"))
    report = render_report(
        "CORE-005",
        {sample.result_id: sample.to_finding()},
        {
            sample.requirement_id: Requirement(
                id=sample.requirement_id,
                title=sample.title or "t",
                category="c",
                severity="Medium",
                how_to_verify="v",
                pass_criteria="p",
            )
        },
        language="en",
    )
    assert "Audit Report" in report


def test_no_production_module_builds_shared_latest_path():
    root = Path(__file__).resolve().parents[1] / "src" / "auditor"
    forbidden = (
        ' / "latest"',
        "/latest/",
        ' / "current"',
        "/current/",
    )
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if path.name in {"run_resolve.py", "legacy_compat.py"}:
            # Documented legacy helpers may mention latest; production resume must not use them.
            continue
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(root.parent.parent)}:{needle}")
    assert not offenders, offenders

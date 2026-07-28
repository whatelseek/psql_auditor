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


# ---------------------------------------------------------------------------
# CORE-005 gap closure: concurrent checkpointers, rebind, Sqlite init failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_arun_one_keeps_isolated_checkpointers(tmp_path: Path):
    """Two concurrent arun_one calls must not replace each other's Sqlite saver."""
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
        max_parallel_assessments=1,
    )
    graph = AuditorGraph(settings=settings)
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha", slug="client_alpha", client_id=CLIENT_ALPHA_ID
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

    gate = asyncio.Event()
    entered: list[str] = []
    real_acquire = __import__(
        "auditor.workflows.runner", fromlist=["acquire_run_checkpointer"]
    ).acquire_run_checkpointer

    async def gated_acquire(runtime, *, client_id, audit_run_id):
        entered.append(audit_run_id)
        # Force both callers to reach init before either finishes.
        if len(entered) < 2:
            await gate.wait()
        else:
            gate.set()
        return await real_acquire(runtime, client_id=client_id, audit_run_id=audit_run_id)

    async def fake_ainvoke(initial, config):
        # Hold briefly so both scoped graphs stay live together.
        await asyncio.sleep(0.05)
        # Prove the captured graph's checkpointer connection is still open.
        return {**initial, "findings": {}, "pending_ids": [], "report": "ok"}

    with patch(
        "auditor.workflows.runner.acquire_run_checkpointer",
        side_effect=gated_acquire,
    ):
        # Patch build so ainvoke is cheap; still use real scoped savers.
        original_build = graph._build

        def build_with_fake(checkpointer=None):
            compiled = original_build(checkpointer=checkpointer)
            compiled.ainvoke = fake_ainvoke  # type: ignore[method-assign]
            return compiled

        with patch.object(graph, "_build", side_effect=build_with_fake):
            r1, r2 = await asyncio.gather(
                graph.arun_one(
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
                ),
                graph.arun_one(
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
                ),
            )

    tid1 = str(r1.get("thread_id") or "")
    tid2 = str(r2.get("thread_id") or "")
    assert tid1 != tid2
    assert RUN_ALPHA_PREVIOUS_ID in tid1
    assert RUN_ALPHA_CURRENT_ID in tid2

    cache = getattr(graph, "_scoped_checkpoints", {})
    b1 = cache[f"{CLIENT_ALPHA_ID}:{RUN_ALPHA_PREVIOUS_ID}"]
    b2 = cache[f"{CLIENT_ALPHA_ID}:{RUN_ALPHA_CURRENT_ID}"]
    assert b1.path != b2.path
    assert b1.path.is_file() and b2.path.is_file()
    assert b1.checkpointer is not b2.checkpointer
    assert b1.conn is not b2.conn
    # Neither connection was closed/replaced during concurrent execution.
    from auditor.workflows.runner import _conn_open

    assert _conn_open(b1.conn)
    assert _conn_open(b2.conn)
    # Persist distinct state into each scoped saver and prove cross-DB isolation.
    cfg1 = {"configurable": {"thread_id": tid1}}
    cfg2 = {"configurable": {"thread_id": tid2}}
    await b1.graph.aupdate_state(
        cfg1,
        {"audit_run_id": RUN_ALPHA_PREVIOUS_ID, "client_id": CLIENT_ALPHA_ID},
        as_node="finalize",
    )
    await b2.graph.aupdate_state(
        cfg2,
        {"audit_run_id": RUN_ALPHA_CURRENT_ID, "client_id": CLIENT_ALPHA_ID},
        as_node="finalize",
    )
    snap1 = await b1.graph.aget_state(cfg1)
    snap2 = await b2.graph.aget_state(cfg2)
    assert snap1.values.get("audit_run_id") == RUN_ALPHA_PREVIOUS_ID
    assert snap2.values.get("audit_run_id") == RUN_ALPHA_CURRENT_ID
    # Cross-read: foreign thread is empty in the other DB.
    foreign = await b1.graph.aget_state(cfg2)
    assert not (foreign.values or {}).get("audit_run_id")


def test_rebind_rejects_foreign_missing_malformed_ownership(tmp_path: Path):
    from auditor.run_scope import OwnershipManifest, write_ownership_manifest

    src = EvidenceStore(tmp_path, run_id="tmp_src_a")
    src.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    # Destination owned by another client.
    foreign = tmp_path / "client_alpha" / RUN_ALPHA_CURRENT_ID
    foreign.mkdir(parents=True)
    (foreign / "marker.txt").write_text("keep", encoding="utf-8")
    write_ownership_manifest(
        foreign,
        OwnershipManifest(client_id=CLIENT_BETA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID),
    )
    src_files_before = sorted(p.name for p in src.root.iterdir())
    dest_files_before = sorted(p.name for p in foreign.iterdir())
    with pytest.raises(OwnershipManifestError):
        src.rebind_run_id(
            f"client_alpha/{RUN_ALPHA_CURRENT_ID}",
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
        )
    assert sorted(p.name for p in src.root.iterdir()) == src_files_before
    assert sorted(p.name for p in foreign.iterdir()) == dest_files_before

    # Missing manifest on non-empty dest.
    missing = tmp_path / "client_alpha" / RUN_ALPHA_PREVIOUS_ID
    missing.mkdir(parents=True)
    (missing / "x.txt").write_text("x", encoding="utf-8")
    src2 = EvidenceStore(tmp_path, run_id="tmp_src_b")
    src2.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID)
    before_src = sorted(p.name for p in src2.root.iterdir())
    before_dest = sorted(p.name for p in missing.iterdir())
    with pytest.raises(OwnershipManifestError):
        src2.rebind_run_id(
            f"client_alpha/{RUN_ALPHA_PREVIOUS_ID}",
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        )
    assert sorted(p.name for p in src2.root.iterdir()) == before_src
    assert sorted(p.name for p in missing.iterdir()) == before_dest

    # Malformed manifest.
    bad = tmp_path / "client_alpha" / "arun_malformed0000001"
    # need valid-looking arun id
    from auditor.client_registry import looks_like_audit_run_id

    arid_bad = "arun_malformed00001"
    assert looks_like_audit_run_id(arid_bad)
    bad = tmp_path / "client_alpha" / arid_bad
    bad.mkdir(parents=True)
    (bad / "ownership.json").write_text("{bad", encoding="utf-8")
    (bad / "y.txt").write_text("y", encoding="utf-8")
    src3 = EvidenceStore(tmp_path, run_id="tmp_src_c")
    src3.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=arid_bad)
    before_src = sorted(p.name for p in src3.root.iterdir())
    before_dest = sorted(p.name for p in bad.iterdir())
    with pytest.raises(OwnershipManifestError):
        src3.rebind_run_id(
            f"client_alpha/{arid_bad}",
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=arid_bad,
        )
    assert sorted(p.name for p in src3.root.iterdir()) == before_src
    assert sorted(p.name for p in bad.iterdir()) == before_dest


def test_rebind_allows_matching_ownership_or_empty_target(tmp_path: Path):
    from auditor.run_scope import OwnershipManifest, write_ownership_manifest

    # Empty / new target.
    src = EvidenceStore(tmp_path, run_id="tmp_new")
    src.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    (src.root / "note.txt").write_text("hello", encoding="utf-8")
    final = src.rebind_run_id(
        f"client_alpha/{RUN_ALPHA_CURRENT_ID}",
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    assert final == f"client_alpha/{RUN_ALPHA_CURRENT_ID}"
    assert (tmp_path / "client_alpha" / RUN_ALPHA_CURRENT_ID / "note.txt").is_file()

    # Matching ownership merge.
    src2 = EvidenceStore(tmp_path, run_id="tmp_merge")
    src2.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    (src2.root / "extra.txt").write_text("more", encoding="utf-8")
    dest = tmp_path / "client_alpha" / RUN_ALPHA_CURRENT_ID
    write_ownership_manifest(
        dest,
        OwnershipManifest(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID),
    )
    src2.rebind_run_id(
        f"client_alpha/{RUN_ALPHA_CURRENT_ID}",
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    assert (dest / "extra.txt").is_file()
    assert (dest / "note.txt").is_file()


@pytest.mark.asyncio
async def test_sqlite_init_failure_is_not_silent_success(tmp_path: Path):
    from auditor.run_scope import CheckpointInitError
    from auditor.workflows.runner import acquire_run_checkpointer

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
    )

    class BoomCM:
        async def __aenter__(self):
            raise OSError("sqlite open failed")

        async def __aexit__(self, *args):
            return False

    with patch(
        "auditor.workflows.runner.AsyncSqliteSaver.from_conn_string",
        return_value=BoomCM(),
    ):
        with pytest.raises(CheckpointInitError):
            await acquire_run_checkpointer(
                graph,
                client_id=CLIENT_ALPHA_ID,
                audit_run_id=RUN_ALPHA_CURRENT_ID,
            )
        with pytest.raises(CheckpointInitError):
            await graph.arun_one(
                "audit",
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


def test_rebind_rewrites_stale_copied_ownership(tmp_path: Path):
    """Moving evidence to a new audit_run path must not keep source ownership.json."""
    from auditor.run_scope import read_ownership_manifest

    src = EvidenceStore(tmp_path, run_id=f"client_alpha/{RUN_ALPHA_PREVIOUS_ID}")
    src.root.mkdir(parents=True, exist_ok=True)
    src.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_PREVIOUS_ID)
    (src.root / "note.txt").write_text("hello", encoding="utf-8")
    assert read_ownership_manifest(src.root).audit_run_id == RUN_ALPHA_PREVIOUS_ID

    final = src.rebind_run_id(
        f"client_alpha/{RUN_ALPHA_CURRENT_ID}",
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    assert final == f"client_alpha/{RUN_ALPHA_CURRENT_ID}"
    dest = tmp_path / "client_alpha" / RUN_ALPHA_CURRENT_ID
    assert (dest / "note.txt").is_file()
    own = read_ownership_manifest(dest)
    assert own.client_id == CLIENT_ALPHA_ID
    assert own.audit_run_id == RUN_ALPHA_CURRENT_ID
    # write_run_meta for the new identity must succeed
    src.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)

"""CORE-006 acceptance tests for ApplicationRuntime production wiring."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from tests.fixtures.canonical_audit import (
    CLIENT_ALPHA_ID,
    RUN_ALPHA_CURRENT_ID,
)

from auditor.application_runtime import (
    ApplicationRuntime,
    RuntimeClosedError,
    RuntimeStartupError,
)
from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry
from auditor.config import Settings
from auditor.graph import AuditorGraph
from auditor.runtime_target import bind_app_settings, effective_settings, get_app_settings
from auditor.tools.mcp_client import McpPoolClosedError
from auditor.workflows.runner import (
    acquire_run_checkpointer,
    release_run_checkpointer,
)


@pytest.mark.asyncio
async def test_two_fastapi_apps_isolated_state(tmp_path: Path) -> None:
    from auditor.api.app import create_app

    ev_a = tmp_path / "ev_a"
    ev_b = tmp_path / "ev_b"
    s1 = Settings(_env_file=None, evidence_dir=ev_a, model_id="runtime-a")
    s2 = Settings(_env_file=None, evidence_dir=ev_b, model_id="runtime-b")

    app1 = create_app(settings=s1)
    app2 = create_app(settings=s2)
    with TestClient(app1) as c1, TestClient(app2) as c2:
        r1 = c1.app.state.runtime
        r2 = c2.app.state.runtime
        assert r1 is not r2
        assert r1.settings.model_id == "runtime-a"
        assert r2.settings.model_id == "runtime-b"
        assert r1.graph is not r2.graph
        assert r1.mcp_pool is not r2.mcp_pool
        assert r1.task_registry is not r2.task_registry
        if r1.results_store is not None and r2.results_store is not None:
            assert r1.results_store is not r2.results_store
        r1.graph._evidence.stores["only-a"] = object()  # type: ignore[assignment]
        assert "only-a" not in r2.graph._evidence.stores


@pytest.mark.asyncio
async def test_same_scope_concurrent_acquire_shared_lease_count(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
    )
    graph = AuditorGraph(settings=settings)
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha",
        slug="client_alpha",
        client_id=CLIENT_ALPHA_ID,
    )
    get_audit_registry(tmp_path).create_run(
        client_id=CLIENT_ALPHA_ID,
        scope={"client_slug": "client_alpha"},
        evidence_run_id="",
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )

    async def _acquire() -> object:
        return await acquire_run_checkpointer(
            graph,
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
        )

    b1, b2 = await asyncio.gather(_acquire(), _acquire())
    assert b1 is b2
    assert b1.lease_count == 2
    await release_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    assert b1.lease_count == 1
    assert not b1.closed
    await release_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    assert b1.lease_count == 0
    assert not b1.closed
    await graph.aclose_runtime_resources()


@pytest.mark.asyncio
async def test_runtime_shutdown_idempotent_and_rejects_work(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path, model_id="shutdown-test")
    runtime = ApplicationRuntime(settings)
    await runtime.start()
    pool = runtime.mcp_pool
    assert runtime.graph is not None
    runtime.graph._evidence.stores["x"] = object()  # type: ignore[assignment]
    assert runtime.graph._evidence.stores
    await runtime.close()
    await runtime.close()
    with pytest.raises(McpPoolClosedError):
        await pool.call_tool("list_schemas", {})
    with pytest.raises(RuntimeClosedError):
        runtime.require_open()
    assert runtime.graph is None


@pytest.mark.asyncio
async def test_partial_startup_failure_closes_resources(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path)

    def boom(_runtime: ApplicationRuntime) -> AuditorGraph:
        raise RuntimeError("graph factory failed")

    runtime = ApplicationRuntime(settings, graph_factory=boom)
    with pytest.raises(RuntimeStartupError):
        await runtime.start()
    assert runtime.state.value == "closed"
    with pytest.raises(McpPoolClosedError):
        await runtime.mcp_pool.reconnect()


@pytest.mark.asyncio
async def test_restart_new_runtime_resumes_scoped_checkpoint(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
    )
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha",
        slug="client_alpha",
        client_id=CLIENT_ALPHA_ID,
    )
    get_audit_registry(tmp_path).create_run(
        client_id=CLIENT_ALPHA_ID,
        scope={"client_slug": "client_alpha"},
        evidence_run_id="",
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )

    runtime_a = ApplicationRuntime(settings)
    await runtime_a.start()
    assert runtime_a.graph is not None
    bundle_a = await acquire_run_checkpointer(
        runtime_a.graph,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    cfg = {"configurable": {"thread_id": f"audit:{CLIENT_ALPHA_ID}:{RUN_ALPHA_CURRENT_ID}"}}
    await bundle_a.graph.aupdate_state(
        cfg,
        {
            "client_id": CLIENT_ALPHA_ID,
            "audit_run_id": RUN_ALPHA_CURRENT_ID,
            "user_request": "paused",
        },
        as_node="finalize",
    )
    db_path = bundle_a.path
    await release_run_checkpointer(
        runtime_a.graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    await runtime_a.close()
    assert db_path.is_file()

    runtime_b = ApplicationRuntime(settings)
    await runtime_b.start()
    assert runtime_b.graph is not None
    bundle_b = await acquire_run_checkpointer(
        runtime_b.graph,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    snap = await bundle_b.graph.aget_state(cfg)
    assert snap.values.get("audit_run_id") == RUN_ALPHA_CURRENT_ID
    await release_run_checkpointer(
        runtime_b.graph,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    await runtime_b.close()


def test_bind_app_settings_restores_after_context(tmp_path: Path) -> None:
    base = Settings(_env_file=None, evidence_dir=tmp_path, model_id="base-model")
    overlay = Settings(_env_file=None, evidence_dir=tmp_path, model_id="overlay-model")
    assert get_app_settings() is None
    with bind_app_settings(base):
        assert get_app_settings() is base
        with bind_app_settings(overlay):
            assert get_app_settings() is overlay
            assert effective_settings().model_id == "overlay-model"
        assert get_app_settings() is base
    assert get_app_settings() is None


@pytest.mark.asyncio
async def test_target_scope_binds_app_settings(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path, pg_host="scope-pg")
    graph = AuditorGraph(settings=settings)

    with graph._target_scope():
        assert effective_settings().pg_host == "scope-pg"
    assert get_app_settings() is None


@pytest.mark.asyncio
async def test_concurrent_runs_on_one_runtime_isolated(tmp_path: Path) -> None:
    """Two audit scopes on one runtime keep separate bundles and evidence."""
    from tests.fixtures.canonical_audit import CLIENT_BETA_ID, RUN_BETA_CURRENT_ID

    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
    )
    get_client_registry(tmp_path).ensure_client(
        display_name="Alpha",
        slug="client_alpha",
        client_id=CLIENT_ALPHA_ID,
    )
    get_client_registry(tmp_path).ensure_client(
        display_name="Beta",
        slug="client_beta",
        client_id=CLIENT_BETA_ID,
    )
    get_audit_registry(tmp_path).create_run(
        client_id=CLIENT_ALPHA_ID,
        scope={"client_slug": "client_alpha"},
        evidence_run_id="",
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    get_audit_registry(tmp_path).create_run(
        client_id=CLIENT_BETA_ID,
        scope={"client_slug": "client_beta"},
        evidence_run_id="",
        audit_run_id=RUN_BETA_CURRENT_ID,
    )

    runtime = ApplicationRuntime(settings)
    await runtime.start()
    assert runtime.graph is not None
    graph = runtime.graph

    b1, b2 = await asyncio.gather(
        acquire_run_checkpointer(
            graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        ),
        acquire_run_checkpointer(graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID),
    )
    assert b1 is not b2
    assert b1.path.resolve() != b2.path.resolve()
    assert b1.client_id != b2.client_id
    assert set(graph._scoped_checkpoints) == {
        f"{CLIENT_ALPHA_ID}:{RUN_ALPHA_CURRENT_ID}",
        f"{CLIENT_BETA_ID}:{RUN_BETA_CURRENT_ID}",
    }
    graph._evidence.stores["alpha-only"] = object()  # type: ignore[assignment]
    graph._multi_sessions[f"audit:{CLIENT_ALPHA_ID}:{RUN_ALPHA_CURRENT_ID}"] = {"k": 1}
    graph._multi_sessions[f"audit:{CLIENT_BETA_ID}:{RUN_BETA_CURRENT_ID}"] = {"k": 2}

    async def _alpha_task() -> None:
        await asyncio.sleep(60)

    async def _beta_task() -> None:
        await asyncio.sleep(60)

    t_alpha = asyncio.create_task(_alpha_task())
    t_beta = asyncio.create_task(_beta_task())
    runtime.task_registry.track(
        "alpha-bg",
        t_alpha,
        owner="test",
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    runtime.task_registry.track(
        "beta-bg",
        t_beta,
        owner="test",
        client_id=CLIENT_BETA_ID,
        audit_run_id=RUN_BETA_CURRENT_ID,
    )
    await runtime.task_registry.cancel_run(
        client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    await asyncio.sleep(0.05)
    assert t_alpha.cancelled() or t_alpha.done()
    assert not t_beta.done()
    assert graph._multi_sessions[f"audit:{CLIENT_BETA_ID}:{RUN_BETA_CURRENT_ID}"]["k"] == 2
    t_beta.cancel()
    await release_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    await release_run_checkpointer(
        graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID
    )
    await runtime.close()

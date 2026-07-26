"""CORE-006 lifecycle race regressions (MCP, tasks, checkpoint leases)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from tests.fixtures.canonical_audit import (
    CLIENT_ALPHA_ID,
    CLIENT_BETA_ID,
    RUN_ALPHA_CURRENT_ID,
    RUN_BETA_CURRENT_ID,
)

from auditor.application_runtime import (
    ApplicationRuntime,
    RuntimeShutdownTimeoutError,
    RuntimeState,
)
from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry
from auditor.config import Settings
from auditor.graph import AuditorGraph
from auditor.run_scope import (
    CheckpointInitError,
    CheckpointScopeBusyError,
)
from auditor.task_registry import (
    TaskRegistry,
    TaskRegistryShutdownTimeoutError,
)
from auditor.tools.mcp_client import (
    McpPoolClosedError,
    McpPoolShutdownTimeoutError,
    PoolState,
    PostgresMcpPool,
    PostgresMcpSession,
)
from auditor.workflows.runner import (
    acquire_run_checkpointer,
    close_run_checkpointer,
    reconnect_run_checkpointer,
    release_run_checkpointer,
    release_run_resources,
)


class _FakeSession(PostgresMcpSession):
    """Deterministic session that blocks until an event is set."""

    def __init__(self, started: asyncio.Event, release: asyncio.Event) -> None:
        super().__init__()
        self.started = started
        self.release = release
        self.close_calls = 0
        self.call_count = 0

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        settings: Any = None,
    ) -> str:
        del tool_name, arguments, settings
        self.call_count += 1
        self.started.set()
        await self.release.wait()
        return "ok"

    async def list_tools(self, settings: Any = None) -> str:
        del settings
        self.started.set()
        await self.release.wait()
        return "tools"

    async def close(self) -> None:
        self.close_calls += 1


def _seed_run(tmp_path: Path, *, client_id: str, audit_run_id: str, slug: str) -> None:
    get_client_registry(tmp_path).ensure_client(
        display_name=slug,
        slug=slug,
        client_id=client_id,
    )
    get_audit_registry(tmp_path).create_run(
        client_id=client_id,
        scope={"client_slug": slug},
        evidence_run_id="",
        audit_run_id=audit_run_id,
    )


@pytest.mark.asyncio
async def test_a_active_mcp_call_versus_shutdown() -> None:
    pool = PostgresMcpPool(size=1, shutdown_timeout=2.0)
    started = asyncio.Event()
    release = asyncio.Event()
    fake = _FakeSession(started, release)

    async def _ensure(settings: Any) -> None:  # noqa: ANN401
        del settings
        if pool._state is not PoolState.OPEN:
            raise McpPoolClosedError("closed")
        if pool._initialized:
            return
        pool._sessions = [fake]
        pool._available = [fake]
        pool._size = 1
        pool._initialized = True

    pool._ensure_unlocked = _ensure  # type: ignore[method-assign]

    active = asyncio.create_task(pool.call_tool("query", {"sql": "select 1"}))
    await started.wait()

    waiting = asyncio.create_task(pool.call_tool("query", {"sql": "select 2"}))
    await asyncio.sleep(0.05)
    closer = asyncio.create_task(pool.close())

    await asyncio.sleep(0.05)
    with pytest.raises(McpPoolClosedError):
        await waiting
    assert not closer.done()
    release.set()
    assert await active == "ok"
    await closer
    assert pool.state is PoolState.CLOSED
    assert fake.close_calls == 1
    await pool.close()  # idempotent
    assert fake.close_calls == 1


@pytest.mark.asyncio
async def test_b_mcp_shutdown_timeout_then_retry() -> None:
    pool = PostgresMcpPool(size=1, shutdown_timeout=0.05)
    started = asyncio.Event()
    release = asyncio.Event()
    fake = _FakeSession(started, release)

    async def _ensure(settings: Any) -> None:  # noqa: ANN401
        del settings
        pool._sessions = [fake]
        pool._available = [fake]
        pool._size = 1
        pool._initialized = True

    pool._ensure_unlocked = _ensure  # type: ignore[method-assign]
    active = asyncio.create_task(pool.call_tool("query", {}))
    await started.wait()
    with pytest.raises(McpPoolShutdownTimeoutError):
        await pool.close(timeout=0.05)
    assert pool.state is PoolState.CLOSING
    assert fake.close_calls == 0
    assert fake in pool._active
    release.set()
    await active
    await pool.close(timeout=1.0)
    assert pool.state is PoolState.CLOSED
    assert fake.close_calls == 1


@pytest.mark.asyncio
async def test_c_cancellation_resistant_background_task() -> None:
    registry = TaskRegistry(shutdown_timeout=0.05)
    release = asyncio.Event()

    async def _resistant() -> None:
        await release.wait()

    task = asyncio.create_task(_resistant())
    # Refuse cancellation so shutdown must time out with a live task.
    task.cancel = lambda *args, **kwargs: False  # type: ignore[method-assign]
    registry.track("resist", task, owner="test")
    with pytest.raises(TaskRegistryShutdownTimeoutError) as exc:
        await registry.shutdown(timeout=0.05)
    assert "resist" in exc.value.keys
    assert registry.get("resist") is not None
    assert registry.closed
    with pytest.raises(Exception):
        registry.track("new", asyncio.create_task(asyncio.sleep(0)))
    release.set()
    # Restore real cancel so final shutdown can finish.
    del task.cancel
    await asyncio.sleep(0.05)
    await registry.shutdown(timeout=1.0)
    assert registry.get("resist") is None


@pytest.mark.asyncio
async def test_d_run_specific_task_cancellation() -> None:
    registry = TaskRegistry(shutdown_timeout=0.05)
    release = asyncio.Event()

    async def _resist() -> None:
        await release.wait()

    async def _other() -> None:
        await asyncio.sleep(3600)

    t1 = asyncio.create_task(_resist())
    t1.cancel = lambda *args, **kwargs: False  # type: ignore[method-assign]
    t2 = asyncio.create_task(_other())
    registry.track(
        "a",
        t1,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    registry.track(
        "b",
        t2,
        client_id=CLIENT_BETA_ID,
        audit_run_id=RUN_BETA_CURRENT_ID,
    )
    with pytest.raises(TaskRegistryShutdownTimeoutError):
        await registry.cancel_run(
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
            timeout=0.05,
        )
    assert registry.get("a") is not None
    assert registry.get("b") is not None
    assert not t2.done()
    release.set()
    del t1.cancel
    await asyncio.sleep(0.05)
    await registry.cancel_run(
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        timeout=1.0,
    )
    assert registry.get("b") is not None
    t2.cancel()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_e_active_checkpoint_lease_versus_cleanup(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path, agents_dir=Path("agents"))
    _seed_run(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        slug="client_alpha",
    )
    _seed_run(
        tmp_path,
        client_id=CLIENT_BETA_ID,
        audit_run_id=RUN_BETA_CURRENT_ID,
        slug="client_beta",
    )
    graph = AuditorGraph(settings=settings)
    leased = await acquire_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    graph._evidence.stores["alpha-ev"] = type(
        "S", (), {"audit_run_id": RUN_ALPHA_CURRENT_ID, "run_id": "alpha-ev"}
    )()
    graph._multi_sessions[f"audit:{CLIENT_ALPHA_ID}:{RUN_ALPHA_CURRENT_ID}"] = {"k": 1}
    other = await acquire_run_checkpointer(
        graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID
    )
    with pytest.raises(CheckpointScopeBusyError):
        await release_run_resources(
            graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        )
    assert leased.scope_key in graph._scoped_checkpoints
    assert not leased.closed
    assert "alpha-ev" in graph._evidence.stores
    assert other.scope_key in graph._scoped_checkpoints
    db_path = leased.path
    await release_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    await release_run_resources(graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    assert leased.scope_key not in graph._scoped_checkpoints
    assert "alpha-ev" not in graph._evidence.stores
    assert db_path.is_file()
    await release_run_resources(graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    await release_run_checkpointer(
        graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID
    )
    await close_run_checkpointer(graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID)


@pytest.mark.asyncio
async def test_f_two_same_scope_leases(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path, agents_dir=Path("agents"))
    _seed_run(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        slug="client_alpha",
    )
    graph = AuditorGraph(settings=settings)
    b1, b2 = await asyncio.gather(
        acquire_run_checkpointer(
            graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        ),
        acquire_run_checkpointer(
            graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        ),
    )
    assert b1 is b2
    assert b1.lease_count == 2
    await release_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    assert b1.lease_count == 1
    with pytest.raises(CheckpointScopeBusyError):
        await close_run_checkpointer(
            graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        )
    with pytest.raises(CheckpointScopeBusyError):
        await reconnect_run_checkpointer(
            graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        )
    await release_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    assert b1.lease_count == 0
    await release_run_resources(graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)


@pytest.mark.asyncio
async def test_g_active_lease_versus_reconnect(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path, agents_dir=Path("agents"))
    _seed_run(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        slug="client_alpha",
    )
    _seed_run(
        tmp_path,
        client_id=CLIENT_BETA_ID,
        audit_run_id=RUN_BETA_CURRENT_ID,
        slug="client_beta",
    )
    graph = AuditorGraph(settings=settings)
    leased = await acquire_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    beta = await acquire_run_checkpointer(
        graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID
    )
    old_graph = leased.graph
    with pytest.raises(CheckpointScopeBusyError):
        await reconnect_run_checkpointer(
            graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        )
    assert graph._scoped_checkpoints[leased.scope_key].graph is old_graph
    await release_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    replaced = await reconnect_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )
    assert replaced.lease_count == 0
    assert replaced.graph is not old_graph
    assert beta.scope_key in graph._scoped_checkpoints
    await release_run_checkpointer(
        graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID
    )
    await close_run_checkpointer(graph, client_id=CLIENT_BETA_ID, audit_run_id=RUN_BETA_CURRENT_ID)
    await close_run_checkpointer(
        graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )


@pytest.mark.asyncio
async def test_h_main_graph_compilation_failure_closes_sqlite(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path, agents_dir=Path("agents"))
    _seed_run(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        slug="client_alpha",
    )
    graph = AuditorGraph(settings=settings)
    exits = {"n": 0}

    class _CM:
        async def __aenter__(self) -> Any:
            return type("CP", (), {"conn": object()})()

        async def __aexit__(self, *args: Any) -> None:
            del args
            exits["n"] += 1

    class _Saver:
        @staticmethod
        def from_conn_string(_path: str) -> _CM:
            return _CM()

    import auditor.workflows.runner as runner_mod

    original = runner_mod.AsyncSqliteSaver
    runner_mod.AsyncSqliteSaver = _Saver  # type: ignore[assignment]
    graph._build = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("build fail"))  # type: ignore[method-assign]
    try:
        with pytest.raises(CheckpointInitError) as exc:
            await acquire_run_checkpointer(
                graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
            )
        assert isinstance(exc.value.__cause__, RuntimeError)
        assert exits["n"] == 1
        assert graph._scoped_checkpoints == {}
    finally:
        runner_mod.AsyncSqliteSaver = original


@pytest.mark.asyncio
async def test_i_intake_graph_compilation_failure_closes_sqlite(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, evidence_dir=tmp_path, agents_dir=Path("agents"))
    _seed_run(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        slug="client_alpha",
    )
    graph = AuditorGraph(settings=settings)
    exits = {"n": 0}

    class _CM:
        async def __aenter__(self) -> Any:
            return type("CP", (), {"conn": object()})()

        async def __aexit__(self, *args: Any) -> None:
            del args
            exits["n"] += 1

    class _Saver:
        @staticmethod
        def from_conn_string(_path: str) -> _CM:
            return _CM()

    import auditor.workflows.runner as runner_mod

    original = runner_mod.AsyncSqliteSaver
    runner_mod.AsyncSqliteSaver = _Saver  # type: ignore[assignment]
    graph._build = lambda *a, **k: object()  # type: ignore[method-assign]
    graph._build_intake = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("intake fail")
    )
    try:
        with pytest.raises(CheckpointInitError) as exc:
            await acquire_run_checkpointer(
                graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
            )
        assert isinstance(exc.value.__cause__, RuntimeError)
        assert exits["n"] == 1
        assert graph._scoped_checkpoints == {}
        # Retry can succeed with restored builders.
        graph._build = AuditorGraph._build.__get__(graph, AuditorGraph)  # type: ignore[method-assign]
        graph._build_intake = AuditorGraph._build_intake.__get__(graph, AuditorGraph)  # type: ignore[method-assign]
    finally:
        runner_mod.AsyncSqliteSaver = original
        # Restore real builders for a successful retry with real sqlite.
        g2 = AuditorGraph(settings=settings)
        b = await acquire_run_checkpointer(
            g2, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        )
        await release_run_checkpointer(
            g2, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        )
        await close_run_checkpointer(
            g2, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
        )
        assert b.path.is_file()


@pytest.mark.asyncio
async def test_j_runtime_shutdown_with_live_resources(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
    )
    _seed_run(
        tmp_path,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        slug="client_alpha",
    )
    runtime = ApplicationRuntime(settings, shutdown_timeout=0.1)
    await runtime.start()
    assert runtime.graph is not None
    leased = await acquire_run_checkpointer(
        runtime.graph, client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID
    )

    hold = asyncio.Event()

    async def _hold() -> None:
        await hold.wait()

    task = asyncio.create_task(_hold())
    task.cancel = lambda *args, **kwargs: False  # type: ignore[method-assign]
    runtime.task_registry.track(
        "live",
        task,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    with pytest.raises(RuntimeShutdownTimeoutError):
        await runtime.close()
    assert runtime.state is RuntimeState.CLOSING
    assert not leased.closed
    hold.set()
    del task.cancel
    await release_run_checkpointer(
        runtime.graph,  # type: ignore[arg-type]
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
    )
    await runtime.close()
    assert runtime.state is RuntimeState.CLOSED

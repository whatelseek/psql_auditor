"""Explicit application-owned runtime lifecycle (CORE-006).

Ownership model::

    create → start → serve requests → close

Every :class:`ApplicationRuntime` instance owns its settings snapshot,
:class:`~auditor.graph.AuditorGraph`, MCP pool, results store, task registry,
and in-memory run registries. Production request paths must resolve this
container from ``request.app.state`` — not module-level singletons.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, contextmanager
from enum import Enum
from typing import TYPE_CHECKING, Any, AsyncIterator, Callable, Iterator

from auditor.config import Settings, load_settings
from auditor.results_store import ResultsStore, bind_results_store
from auditor.runtime_target import bind_app_settings
from auditor.task_registry import TaskRegistry
from auditor.tools.mcp_client import PostgresMcpPool

if TYPE_CHECKING:
    from auditor.graph import AuditorGraph

logger = logging.getLogger(__name__)


class RuntimeState(str, Enum):
    """Lifecycle states for :class:`ApplicationRuntime`."""

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    CLOSING = "closing"
    CLOSED = "closed"


class RuntimeStartupError(RuntimeError):
    """Raised when application runtime initialization fails."""


class RuntimeClosedError(RuntimeError):
    """Raised when work is attempted on a closing or closed runtime."""


class RuntimeShutdownTimeoutError(RuntimeError):
    """Raised when owned resources do not close within the shutdown timeout."""


class ApplicationRuntime:
    """Application-owned container for settings, graph, stores, and pools."""

    def __init__(
        self,
        settings: Settings,
        *,
        mcp_pool: PostgresMcpPool | None = None,
        results_store: ResultsStore | None = None,
        task_registry: TaskRegistry | None = None,
        graph_factory: Callable[["ApplicationRuntime"], "AuditorGraph"] | None = None,
        shutdown_timeout: float = 10.0,
    ) -> None:
        self.settings = settings
        self.shutdown_timeout = shutdown_timeout
        self.state = RuntimeState.CREATED
        self.mcp_pool = mcp_pool or PostgresMcpPool(size=settings.mcp_postgres_pool_size)
        self._owns_mcp_pool = mcp_pool is None
        if results_store is not None:
            self.results_store: ResultsStore | None = results_store
        else:
            candidate = ResultsStore(settings)
            self.results_store = candidate if candidate.enabled else None
        self.task_registry = task_registry or TaskRegistry(
            shutdown_timeout=min(5.0, shutdown_timeout)
        )
        self._graph_factory = graph_factory
        self.graph: AuditorGraph | None = None
        self._start_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()

    def require_open(self) -> None:
        """Reject work once shutdown has begun."""
        if self.state != RuntimeState.RUNNING:
            raise RuntimeClosedError(
                f"application runtime is {self.state.value}; refusing new work"
            )

    @contextmanager
    def bind(self) -> Iterator["ApplicationRuntime"]:
        """Bind settings/results ContextVars for the current task."""
        with bind_app_settings(self.settings), bind_results_store(self.results_store):
            yield self

    async def start(self) -> "ApplicationRuntime":
        """Initialize owned resources. Safe to call once; re-entrant when running."""
        async with self._start_lock:
            if self.state is RuntimeState.RUNNING:
                return self
            if self.state in (RuntimeState.CLOSING, RuntimeState.CLOSED):
                raise RuntimeClosedError("cannot start a closed application runtime")
            self.state = RuntimeState.STARTING
            try:
                from auditor.graph import AuditorGraph

                if self._graph_factory is not None:
                    self.graph = self._graph_factory(self)
                else:
                    self.graph = AuditorGraph(
                        settings=self.settings,
                        mcp_pool=self.mcp_pool,
                        results_store=self.results_store,
                        task_registry=self.task_registry,
                    )
                self.state = RuntimeState.RUNNING
                return self
            except Exception as exc:
                logger.exception("application runtime startup failed")
                await self._close_unlocked(reason="startup_failure")
                raise RuntimeStartupError(f"application runtime startup failed: {exc}") from exc

    async def close(self) -> None:
        """Idempotent shutdown of all owned resources."""
        async with self._close_lock:
            await self._close_unlocked(reason="shutdown")

    async def _close_unlocked(self, *, reason: str) -> None:
        if self.state is RuntimeState.CLOSED:
            return
        self.state = RuntimeState.CLOSING
        errors: list[str] = []
        try:
            await self.task_registry.shutdown(timeout=self.shutdown_timeout)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"task_registry: {exc}")
        graph = self.graph
        if graph is not None:
            try:
                await graph.aclose_runtime_resources(timeout=self.shutdown_timeout)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"graph: {exc}")
            self.graph = None
        if self._owns_mcp_pool:
            try:
                await self.mcp_pool.close()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"mcp_pool: {exc}")
        self.state = RuntimeState.CLOSED
        if errors:
            raise RuntimeShutdownTimeoutError(
                f"runtime close incomplete ({reason}): {'; '.join(errors)}"
            )

    async def release_run_resources(
        self,
        *,
        client_id: str,
        audit_run_id: str,
    ) -> None:
        """Release in-memory resources for one terminal/abandoned audit run."""
        self.require_open()
        assert self.graph is not None
        from auditor.workflows.runner import release_run_resources

        await release_run_resources(
            self.graph,
            client_id=client_id,
            audit_run_id=audit_run_id,
        )

    async def reconnect_run_checkpointer(
        self,
        *,
        client_id: str,
        audit_run_id: str,
    ) -> Any:
        """Reconnect only the scoped bundle for one run (never the whole runtime)."""
        self.require_open()
        assert self.graph is not None
        from auditor.workflows.runner import reconnect_run_checkpointer

        return await reconnect_run_checkpointer(
            self.graph,
            client_id=client_id,
            audit_run_id=audit_run_id,
        )


async def build_application_runtime(
    settings: Settings | None = None,
) -> ApplicationRuntime:
    """Compose and start a runtime from an optional settings snapshot."""
    snap = settings if settings is not None else load_settings()
    runtime = ApplicationRuntime(snap)
    await runtime.start()
    return runtime


@asynccontextmanager
async def runtime_lifespan(
    settings: Settings | None = None,
    *,
    runtime_factory: Callable[[], Any] | None = None,
) -> AsyncIterator[ApplicationRuntime]:
    """Async context that starts a runtime and always closes it."""
    runtime: ApplicationRuntime | None = None
    try:
        if runtime_factory is not None:
            produced = runtime_factory()
            runtime = await produced if asyncio.iscoroutine(produced) else produced
            if runtime.state is not RuntimeState.RUNNING:
                await runtime.start()
        else:
            runtime = await build_application_runtime(settings)
        yield runtime
    finally:
        if runtime is not None:
            await runtime.close()

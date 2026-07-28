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
import time
from contextlib import asynccontextmanager, contextmanager
from enum import Enum
from typing import TYPE_CHECKING, Any, AsyncIterator, Callable, Iterator

from auditor.config import Settings, load_settings
from auditor.results_store import ResultsStore, bind_results_store
from auditor.runtime_target import bind_app_settings
from auditor.task_registry import TaskRegistry, TaskRegistryShutdownTimeoutError
from auditor.tools.mcp_client import McpPoolShutdownTimeoutError, PoolState, PostgresMcpPool

if TYPE_CHECKING:
    from auditor.graph import AuditorGraph
    from auditor.tool_registry import ToolRegistry

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
        tool_registry: "ToolRegistry | None" = None,
        graph_factory: Callable[["ApplicationRuntime"], "AuditorGraph"] | None = None,
        shutdown_timeout: float = 10.0,
    ) -> None:
        self.settings = settings
        self.shutdown_timeout = shutdown_timeout
        self.state = RuntimeState.CREATED
        self.mcp_pool = mcp_pool or PostgresMcpPool(
            size=settings.mcp_postgres_pool_size,
            shutdown_timeout=min(5.0, shutdown_timeout),
        )
        self._owns_mcp_pool = mcp_pool is None
        if results_store is not None:
            self.results_store: ResultsStore | None = results_store
        else:
            candidate = ResultsStore(settings)
            self.results_store = candidate if candidate.enabled else None
        self.task_registry = task_registry or TaskRegistry(
            shutdown_timeout=min(5.0, shutdown_timeout)
        )
        self.tool_registry: ToolRegistry | None = tool_registry
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
                from auditor.domain.audit_request import POC_TOOL_PROFILE
                from auditor.graph import AuditorGraph
                from auditor.tool_registry import (
                    REQUIRED_POC_SSH_TOOL_IDS,
                    load_tool_registry,
                    validate_runtime_tool_registry,
                )

                if self.tool_registry is None:
                    self.tool_registry = load_tool_registry(
                        self.settings.tools_dir,
                        profile=POC_TOOL_PROFILE,
                    )

                validate_runtime_tool_registry(
                    self.tool_registry,
                    required_tool_ids=REQUIRED_POC_SSH_TOOL_IDS,
                    tools_dir=self.settings.tools_dir,
                    expected_profile=POC_TOOL_PROFILE,
                )

                if self._graph_factory is not None:
                    self.graph = self._graph_factory(self)
                else:
                    self.graph = AuditorGraph(
                        settings=self.settings,
                        mcp_pool=self.mcp_pool,
                        results_store=self.results_store,
                        task_registry=self.task_registry,
                        tool_registry=self.tool_registry,
                    )
                self.state = RuntimeState.RUNNING
                return self
            except Exception as exc:
                from auditor.tool_registry import RuntimeToolCatalogError

                if isinstance(exc, RuntimeToolCatalogError):
                    logger.error(
                        "application runtime startup failed: code=%s tool=%s profile=%s",
                        exc.code,
                        exc.tool_id or "-",
                        exc.policy_profile or "-",
                    )
                    detail = f"code={exc.code}"
                    if exc.tool_id:
                        detail = f"{detail} tool={exc.tool_id}"
                    if exc.policy_profile:
                        detail = f"{detail} profile={exc.policy_profile}"
                    startup_message = f"application runtime startup failed: {detail}"
                else:
                    logger.exception("application runtime startup failed")
                    startup_message = "application runtime startup failed"
                try:
                    await self._close_unlocked(reason="startup_failure")
                except RuntimeShutdownTimeoutError:
                    logger.warning("startup failure cleanup timed out; runtime left CLOSING")
                raise RuntimeStartupError(startup_message) from exc

    async def close(self) -> None:
        """Idempotent shutdown of all owned resources.

        ``CLOSED → close()`` is a no-op. ``CLOSING → close()`` resumes drain
        under the remaining overall deadline. Success transitions to ``CLOSED``
        only after all owned resources are actually closed.
        """
        async with self._close_lock:
            await self._close_unlocked(reason="shutdown")

    def _remaining(self, deadline: float) -> float:
        return max(0.0, deadline - time.monotonic())

    async def _close_unlocked(self, *, reason: str) -> None:
        if self.state is RuntimeState.CLOSED:
            return
        # Resume incomplete shutdown or begin a new one with one monotonic deadline.
        self.state = RuntimeState.CLOSING
        deadline = time.monotonic() + self.shutdown_timeout
        try:
            try:
                await self.task_registry.shutdown(timeout=self._remaining(deadline))
            except TaskRegistryShutdownTimeoutError as exc:
                raise RuntimeShutdownTimeoutError(
                    f"runtime close incomplete ({reason}): task_registry: {exc}"
                ) from exc

            graph = self.graph
            if graph is not None:
                try:
                    await graph.aclose_runtime_resources(timeout=self._remaining(deadline))
                except Exception as exc:  # noqa: BLE001
                    # Keep graph reference so a later close can retry draining leases.
                    raise RuntimeShutdownTimeoutError(
                        f"runtime close incomplete ({reason}): graph: {exc}"
                    ) from exc
                self.graph = None

            if self._owns_mcp_pool and self.mcp_pool.state is not PoolState.CLOSED:
                try:
                    await self.mcp_pool.close(timeout=self._remaining(deadline))
                except McpPoolShutdownTimeoutError as exc:
                    raise RuntimeShutdownTimeoutError(
                        f"runtime close incomplete ({reason}): mcp_pool: {exc}"
                    ) from exc

            self.state = RuntimeState.CLOSED
        except RuntimeShutdownTimeoutError:
            # Remain CLOSING; do not force-close live dependencies.
            self.state = RuntimeState.CLOSING
            raise

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

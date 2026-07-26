"""Owned registry for background / orphan asyncio tasks (CORE-006)."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class TaskRegistryError(RuntimeError):
    """Raised when task registry operations are invalid after shutdown."""


class TaskRegistryShutdownTimeoutError(TaskRegistryError):
    """Raised when tracked tasks remain alive after a shutdown/cancel deadline."""

    def __init__(self, message: str, *, keys: list[str] | None = None) -> None:
        super().__init__(message)
        self.keys = list(keys or [])


@dataclass
class TrackedTask:
    """One background task with stable owner / run identity."""

    key: str
    task: asyncio.Task[Any]
    owner: str | None = None
    client_id: str | None = None
    audit_run_id: str | None = None
    exception: BaseException | None = None


@dataclass
class TaskRegistry:
    """Track detached audit/stream tasks with observed exceptions."""

    shutdown_timeout: float = 5.0
    _tasks: dict[str, TrackedTask] = field(default_factory=dict)
    _closed: bool = False
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def track(
        self,
        key: str,
        task: asyncio.Task[Any],
        *,
        owner: str | None = None,
        client_id: str | None = None,
        audit_run_id: str | None = None,
    ) -> asyncio.Task[Any]:
        """Register ``task`` under ``key``; completed tasks remove themselves."""
        if self._closed:
            raise TaskRegistryError("cannot track tasks on a closed registry")
        existing = self._tasks.get(key)
        if existing is not None and not existing.task.done():
            raise TaskRegistryError(f"task key already active: {key}")
        tracked = TrackedTask(
            key=key,
            task=task,
            owner=owner,
            client_id=client_id,
            audit_run_id=audit_run_id,
        )
        self._tasks[key] = tracked

        def _done(t: asyncio.Task[Any]) -> None:
            exc: BaseException | None
            try:
                exc = t.exception()
            except asyncio.CancelledError as cancel:
                exc = cancel
            except Exception as unexpected:  # noqa: BLE001
                exc = unexpected
            tracked.exception = exc
            if exc is not None and not isinstance(exc, asyncio.CancelledError):
                logger.warning(
                    "background task %s failed: %s: %s",
                    key,
                    type(exc).__name__,
                    exc,
                )
            # Only forget when truly done; keep entry if somehow re-registered.
            current = self._tasks.get(key)
            if current is tracked and t.done():
                self._tasks.pop(key, None)

        task.add_done_callback(_done)
        return task

    def get(self, key: str) -> TrackedTask | None:
        return self._tasks.get(key)

    def keys(self) -> list[str]:
        return list(self._tasks)

    @property
    def closed(self) -> bool:
        return self._closed

    def tasks_for_run(self, *, client_id: str, audit_run_id: str) -> list[TrackedTask]:
        return [
            t
            for t in self._tasks.values()
            if t.client_id == client_id and t.audit_run_id == audit_run_id
        ]

    def _consume_done(self, tracked: TrackedTask) -> None:
        if not tracked.task.done():
            return
        try:
            tracked.task.exception()
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    async def cancel_run(
        self,
        *,
        client_id: str,
        audit_run_id: str,
        timeout: float | None = None,
    ) -> None:
        """Cancel tasks owned by one audit run; leave other runs untouched.

        Raises:
            TaskRegistryShutdownTimeoutError: when targeted tasks remain alive.
        """
        targets = self.tasks_for_run(client_id=client_id, audit_run_id=audit_run_id)
        if not targets:
            return
        for tracked in targets:
            tracked.task.cancel()
        wait_timeout = timeout if timeout is not None else self.shutdown_timeout
        _done, pending = await asyncio.wait(
            [t.task for t in targets],
            timeout=wait_timeout,
        )
        for tracked in targets:
            if tracked.task.done():
                self._consume_done(tracked)
        alive = [t for t in targets if not t.task.done()]
        if alive or pending:
            keys = [t.key for t in alive]
            raise TaskRegistryShutdownTimeoutError(
                "cancel_run timed out with live tasks: " + ", ".join(keys),
                keys=keys,
            )

    async def shutdown(self, timeout: float | None = None) -> None:
        """Cancel and await remaining tasks with a bounded timeout.

        Sets closed before cancellation so new tasks cannot be registered.
        Retains every still-running task; a later ``shutdown()`` retries drain.
        Succeeds only when no tracked tasks remain active.
        """
        async with self._lock:
            self._closed = True
            pending_tracked = [t for t in list(self._tasks.values()) if not t.task.done()]
            for tracked in pending_tracked:
                tracked.task.cancel()
            if pending_tracked:
                wait_timeout = timeout if timeout is not None else self.shutdown_timeout
                _done, still_pending = await asyncio.wait(
                    [t.task for t in pending_tracked],
                    timeout=wait_timeout,
                )
            else:
                still_pending = set()
            for tracked in pending_tracked:
                if tracked.task.done():
                    self._consume_done(tracked)
            alive = [t for t in list(self._tasks.values()) if not t.task.done()]
            if alive or still_pending:
                keys = sorted({t.key for t in alive})
                raise TaskRegistryShutdownTimeoutError(
                    "task registry shutdown timed out; live keys: " + ", ".join(keys),
                    keys=keys,
                )
            # All tracked tasks are done; clear any residual done entries.
            self._tasks.clear()

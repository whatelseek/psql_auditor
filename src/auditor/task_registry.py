"""Owned registry for background / orphan asyncio tasks (CORE-006)."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class TaskRegistryError(RuntimeError):
    """Raised when task registry operations are invalid after shutdown."""


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
            self._tasks.pop(key, None)

        task.add_done_callback(_done)
        return task

    def get(self, key: str) -> TrackedTask | None:
        return self._tasks.get(key)

    def keys(self) -> list[str]:
        return list(self._tasks)

    def tasks_for_run(self, *, client_id: str, audit_run_id: str) -> list[TrackedTask]:
        return [
            t
            for t in self._tasks.values()
            if t.client_id == client_id and t.audit_run_id == audit_run_id
        ]

    async def cancel_run(
        self,
        *,
        client_id: str,
        audit_run_id: str,
        timeout: float | None = None,
    ) -> None:
        """Cancel tasks owned by one audit run; leave other runs untouched."""
        targets = self.tasks_for_run(client_id=client_id, audit_run_id=audit_run_id)
        for tracked in targets:
            tracked.task.cancel()
        if not targets:
            return
        await asyncio.wait(
            [t.task for t in targets],
            timeout=timeout if timeout is not None else self.shutdown_timeout,
        )
        for tracked in targets:
            if tracked.task.done():
                try:
                    tracked.task.exception()
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass

    async def shutdown(self, timeout: float | None = None) -> None:
        """Cancel and await remaining tasks with a bounded timeout (idempotent)."""
        async with self._lock:
            self._closed = True
            pending = [t.task for t in list(self._tasks.values()) if not t.task.done()]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.wait(
                    pending,
                    timeout=timeout if timeout is not None else self.shutdown_timeout,
                )
            for task in pending:
                if task.done():
                    try:
                        task.exception()
                    except (asyncio.CancelledError, Exception):  # noqa: BLE001
                        pass
            self._tasks.clear()

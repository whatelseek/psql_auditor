"""Per-run progress bus for live Open WebUI tool and reasoning streams.

Active during a single audit or ad-hoc command run when the API binds a
:class:`ProgressSink` via :func:`bind_progress_sink`. Graph nodes and tools call
:func:`emit_progress` (and convenience wrappers) to push structured events into
an asyncio queue; the FastAPI SSE adapter drains that queue for Open WebUI.

Events are fire-and-forget: if no sink is bound, emits are silently dropped.
This keeps library code usable outside the HTTP server without side effects.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterator, Literal

ProgressKind = Literal[
    "reasoning",
    "tool_call",
    "tool_result",
    "req_status",
    "phase",
]

_STREAM_TRUNCATE = 1200

_current_sink: ContextVar["ProgressSink | None"] = ContextVar(
    "auditor_progress_sink", default=None
)


@dataclass(slots=True)
class ProgressEvent:
    """One live progress event for SSE adapters and chat UI rendering.

  Serialized by the API layer into Server-Sent Events so operators see tool
  calls, reasoning snippets, per-requirement status changes, and phase labels
  in real time during long audit runs.

  Attributes:
      kind: Event category (reasoning, tool_call, tool_result, req_status, phase).
      text: Human-readable message or reasoning excerpt.
      tool_name: Tool identifier for tool_call / tool_result events.
      tool_call_id: Correlates a tool call with its result.
      arguments: Tool input payload (dict or wrapped scalar).
      result: Truncated tool output or error text.
      requirement_id: Associated checklist id (``REQ-NNN``) when applicable.
      framework_id: Framework slug when running multi-framework audits.
      status: Sub-status for tool results (``ok`` / ``error``) or REQ status.
      extra: Optional extension fields for forward-compatible metadata.
  """

    kind: ProgressKind
    text: str = ""
    tool_name: str = ""
    tool_call_id: str = ""
    arguments: dict[str, Any] | str | None = None
    result: str = ""
    requirement_id: str = ""
    framework_id: str = ""
    status: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class ProgressSink:
    """Async queue of progress events; ``None`` sentinel marks end-of-stream.

  Created per HTTP request or graph invocation. Producers call :meth:`emit`;
  consumers await :attr:`queue.get` until :meth:`close` enqueues a ``None``
  sentinel. The sink ignores further emits after close.
  """

    def __init__(self) -> None:
        """Initialize an open sink with an unbounded asyncio queue."""
        self.queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()
        self._closed = False

    def emit(self, event: ProgressEvent) -> None:
        """Enqueue an event unless the sink is already closed.

        Drops the event silently on :class:`asyncio.QueueFull` (should not occur
        with the default unbounded queue, but guards misconfiguration).

        Args:
            event: Progress payload to deliver to SSE consumers.
        """
        if self._closed:
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    def close(self) -> None:
        """Mark the sink closed and enqueue the end-of-stream sentinel.

        Idempotent: repeated calls after the first close are no-ops.
        """
        if self._closed:
            return
        self._closed = True
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            pass


def get_progress_sink() -> ProgressSink | None:
    """Return the progress sink bound to the current async context, if any.

    Uses a :class:`contextvars.ContextVar` so concurrent audit runs on the
    same process do not cross-contaminate progress streams.

    Returns:
        The active :class:`ProgressSink`, or ``None`` when no sink is bound.
    """
    return _current_sink.get()


@contextmanager
def bind_progress_sink(sink: ProgressSink | None) -> Iterator[ProgressSink | None]:
    """Context manager that sets the current thread/task progress sink.

    Restores the previous sink (or lack thereof) on exit, even if an exception
    is raised inside the ``with`` block.

    Args:
        sink: Sink to bind for the duration of the context, or ``None`` to clear.

    Yields:
        The same ``sink`` argument for convenience.
    """
    token = _current_sink.set(sink)
    try:
        yield sink
    finally:
        _current_sink.reset(token)


def emit_progress(event: ProgressEvent) -> None:
    """Emit a progress event to the bound sink, if one exists.

    No-op when :func:`get_progress_sink` returns ``None``.

    Args:
        event: Fully constructed progress event.
    """
    sink = get_progress_sink()
    if sink is not None:
        sink.emit(event)


def emit_phase(text: str, *, framework_id: str = "") -> None:
    """Emit a high-level phase label (e.g. "Loading checklist").

    Args:
        text: Phase description shown in the live stream.
        framework_id: Optional framework slug for multi-standard runs.
    """
    emit_progress(
        ProgressEvent(kind="phase", text=text, framework_id=framework_id)
    )


def emit_req_status(
    req_id: str,
    status: str,
    *,
    framework_id: str = "",
    text: str = "",
) -> None:
    """Emit a per-requirement status change for the live checklist view.

    Args:
        req_id: Checklist requirement id (``REQ-NNN``).
        status: Assessment status (``pass``, ``fail``, etc.).
        framework_id: Optional framework slug.
        text: Override display text; defaults to ``REQ-NNN → status``.
    """
    emit_progress(
        ProgressEvent(
            kind="req_status",
            requirement_id=req_id,
            framework_id=framework_id,
            status=status,
            text=text or f"`{req_id}` → {status}",
        )
    )


def emit_tool_call(
    name: str,
    args: Any,
    *,
    call_id: str = "",
    requirement_id: str = "",
    framework_id: str = "",
) -> str:
    """Emit a tool invocation event and return its correlation id.

    Args:
        name: Tool name (e.g. ``ssh_run``, ``mcp_query``).
        args: Tool arguments; non-dicts are wrapped as ``{"value": args}``.
        call_id: Optional existing id; a random id is generated when empty.
        requirement_id: Optional ``REQ-NNN`` context.
        framework_id: Optional framework slug.

    Returns:
        The ``tool_call_id`` used for the matching :func:`emit_tool_result`.
    """
    tid = call_id or f"call_{uuid.uuid4().hex[:16]}"
    emit_progress(
        ProgressEvent(
            kind="tool_call",
            tool_name=name,
            tool_call_id=tid,
            arguments=args if isinstance(args, dict) else {"value": args},
            requirement_id=requirement_id,
            framework_id=framework_id,
        )
    )
    return tid


def emit_tool_result(
    name: str,
    result: str,
    *,
    call_id: str,
    requirement_id: str = "",
    framework_id: str = "",
    error: str | None = None,
) -> None:
    """Emit a tool result (or error) correlated to a prior tool call.

    Result text is truncated via :func:`truncate_for_stream` before enqueue.

    Args:
        name: Tool name matching the original call.
        result: Raw tool stdout/return value.
        call_id: Id returned by :func:`emit_tool_call`.
        requirement_id: Optional ``REQ-NNN`` context.
        framework_id: Optional framework slug.
        error: When set, displayed instead of ``result`` and status is ``error``.
    """
    emit_progress(
        ProgressEvent(
            kind="tool_result",
            tool_name=name,
            tool_call_id=call_id,
            result=truncate_for_stream(error or result),
            requirement_id=requirement_id,
            framework_id=framework_id,
            status="error" if error else "ok",
        )
    )


def truncate_for_stream(text: str, limit: int = _STREAM_TRUNCATE) -> str:
    """Truncate text for SSE payloads with a visible ellipsis marker.

    Args:
        text: Raw string to send to the client.
        limit: Maximum character length before truncation.

    Returns:
        Original text if within ``limit``; otherwise a prefix plus ``…[truncated]``.
    """
    raw = str(text or "")
    if len(raw) <= limit:
        return raw
    return raw[: limit - 20] + "\n…[truncated]"


def args_for_stream(args: Any) -> str:
    """Serialize tool arguments to a compact JSON string for streaming.

    Falls back to ``str(args)`` when JSON encoding fails. Output is truncated
    to 800 characters for UI safety.

    Args:
        args: Tool arguments of any JSON-serializable shape.

    Returns:
        Truncated JSON or string representation suitable for SSE display.
    """
    try:
        blob = json.dumps(args, ensure_ascii=False, default=str)
    except TypeError:
        blob = str(args)
    return truncate_for_stream(blob, 800)

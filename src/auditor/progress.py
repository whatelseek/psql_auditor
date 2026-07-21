"""Per-run progress bus for live Open WebUI tool / reasoning streams."""

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
    """One live progress event for SSE adapters."""

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
    """Async queue of progress events; ``None`` sentinel marks end-of-stream."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()
        self._closed = False

    def emit(self, event: ProgressEvent) -> None:
        if self._closed:
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            pass


def get_progress_sink() -> ProgressSink | None:
    return _current_sink.get()


@contextmanager
def bind_progress_sink(sink: ProgressSink | None) -> Iterator[ProgressSink | None]:
    token = _current_sink.set(sink)
    try:
        yield sink
    finally:
        _current_sink.reset(token)


def emit_progress(event: ProgressEvent) -> None:
    sink = get_progress_sink()
    if sink is not None:
        sink.emit(event)


def emit_phase(text: str, *, framework_id: str = "") -> None:
    emit_progress(
        ProgressEvent(kind="phase", text=text, framework_id=framework_id)
    )


def emit_reasoning(text: str, *, framework_id: str = "", requirement_id: str = "") -> None:
    emit_progress(
        ProgressEvent(
            kind="reasoning",
            text=text,
            framework_id=framework_id,
            requirement_id=requirement_id,
        )
    )


def emit_req_status(
    req_id: str,
    status: str,
    *,
    framework_id: str = "",
    text: str = "",
) -> None:
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
    raw = str(text or "")
    if len(raw) <= limit:
        return raw
    return raw[: limit - 20] + "\n…[truncated]"


def args_for_stream(args: Any) -> str:
    try:
        blob = json.dumps(args, ensure_ascii=False, default=str)
    except TypeError:
        blob = str(args)
    return truncate_for_stream(blob, 800)

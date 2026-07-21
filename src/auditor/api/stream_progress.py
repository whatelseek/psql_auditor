"""SSE helpers: map ProgressEvent → OpenAI chat-completions / Responses chunks."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from auditor.progress import (
    ProgressEvent,
    ProgressSink,
    args_for_stream,
    bind_progress_sink,
)


def _chat_chunk(
    model: str,
    completion_id: str,
    *,
    delta: dict[str, Any],
    finish: str | None = None,
) -> str:
    payload: dict[str, Any] = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": delta,
                "finish_reason": finish,
            }
        ],
    }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def chat_progress_chunks(
    event: ProgressEvent,
    *,
    model: str,
    completion_id: str,
    tool_index: int,
) -> list[str]:
    """OpenAI chat-completions SSE for one progress event."""
    out: list[str] = []
    if event.kind in ("reasoning", "phase", "req_status"):
        text = event.text or ""
        if event.kind == "req_status" and event.requirement_id:
            text = text or f"`{event.requirement_id}` → {event.status}"
        if text:
            # Prefer reasoning_content when clients support it; also send content.
            out.append(
                _chat_chunk(
                    model,
                    completion_id,
                    delta={"reasoning_content": text + "\n"},
                )
            )
            out.append(
                _chat_chunk(
                    model,
                    completion_id,
                    delta={"content": f"_{text}_\n"},
                )
            )
        return out

    if event.kind == "tool_call":
        args = args_for_stream(event.arguments)
        out.append(
            _chat_chunk(
                model,
                completion_id,
                delta={
                    "tool_calls": [
                        {
                            "index": tool_index,
                            "id": event.tool_call_id,
                            "type": "function",
                            "function": {
                                "name": event.tool_name,
                                "arguments": args,
                            },
                        }
                    ]
                },
            )
        )
        return out

    if event.kind == "tool_result":
        # Assistant-visible note + synthetic tool role content via content delta
        preview = event.result or ""
        label = event.tool_name or "tool"
        out.append(
            _chat_chunk(
                model,
                completion_id,
                delta={
                    "content": (
                        f"\n**{label}**"
                        + (f" (`{event.requirement_id}`)" if event.requirement_id else "")
                        + f" →\n```\n{preview}\n```\n"
                    )
                },
            )
        )
        return out

    return out


def responses_progress_events(
    event: ProgressEvent,
    *,
    response_id: str,
    seq_fn: Callable[[], int],
    message_id: str,
) -> list[dict[str, Any]]:
    """OpenAI Responses API event dicts for one progress event."""
    events: list[dict[str, Any]] = []
    if event.kind in ("reasoning", "phase", "req_status"):
        text = event.text or ""
        if event.kind == "req_status" and event.requirement_id:
            text = text or f"`{event.requirement_id}` → {event.status}"
        if not text:
            return events
        # reasoning summary + visible text
        events.append(
            {
                "type": "response.reasoning_summary_text.delta",
                "item_id": message_id,
                "output_index": 0,
                "delta": text + "\n",
                "sequence_number": seq_fn(),
            }
        )
        events.append(
            {
                "type": "response.output_text.delta",
                "item_id": message_id,
                "output_index": 0,
                "content_index": 0,
                "delta": f"_{text}_\n",
                "sequence_number": seq_fn(),
            }
        )
        return events

    if event.kind == "tool_call":
        call_id = event.tool_call_id or f"fc_{uuid.uuid4().hex[:16]}"
        args = args_for_stream(event.arguments)
        events.append(
            {
                "type": "response.output_item.added",
                "output_index": 1,
                "item": {
                    "id": call_id,
                    "type": "function_call",
                    "status": "in_progress",
                    "name": event.tool_name,
                    "call_id": call_id,
                    "arguments": "",
                },
                "sequence_number": seq_fn(),
            }
        )
        events.append(
            {
                "type": "response.function_call_arguments.delta",
                "item_id": call_id,
                "output_index": 1,
                "delta": args,
                "sequence_number": seq_fn(),
            }
        )
        events.append(
            {
                "type": "response.function_call_arguments.done",
                "item_id": call_id,
                "output_index": 1,
                "arguments": args,
                "sequence_number": seq_fn(),
            }
        )
        return events

    if event.kind == "tool_result":
        preview = event.result or ""
        label = event.tool_name or "tool"
        events.append(
            {
                "type": "response.output_text.delta",
                "item_id": message_id,
                "output_index": 0,
                "content_index": 0,
                "delta": (
                    f"\n**{label}**"
                    + (f" (`{event.requirement_id}`)" if event.requirement_id else "")
                    + f" →\n```\n{preview}\n```\n"
                ),
                "sequence_number": seq_fn(),
            }
        )
        return events

    return events


async def run_with_progress(
    coro_factory: Callable[[], Awaitable[dict[str, Any]]],
    *,
    on_event: Callable[[ProgressEvent], Awaitable[None] | None],
) -> dict[str, Any]:
    """Run audit coroutine while draining a ProgressSink to ``on_event``."""
    sink = ProgressSink()
    result_box: dict[str, Any] = {}
    error_box: list[BaseException] = []

    async def _runner() -> None:
        with bind_progress_sink(sink):
            try:
                result_box["result"] = await coro_factory()
            except BaseException as exc:  # noqa: BLE001
                error_box.append(exc)
            finally:
                sink.close()

    task = asyncio.create_task(_runner())
    try:
        while True:
            event = await sink.queue.get()
            if event is None:
                break
            maybe = on_event(event)
            if asyncio.iscoroutine(maybe) or isinstance(maybe, Awaitable):
                await maybe  # type: ignore[arg-type]
        await task
    except asyncio.CancelledError:
        # Keep graph running as orphan — caller may shield the task separately.
        raise
    if error_box:
        raise error_box[0]
    return result_box.get("result") or {}

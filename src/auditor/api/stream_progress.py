"""SSE helpers: map ``ProgressEvent`` → OpenAI chat-completions / Responses chunks.

Pipeline role:
    During streaming audits, the graph emits ``ProgressEvent`` objects (phase
    changes, tool calls, requirement status). This module translates those
    internal events into wire-format SSE payloads understood by Open WebUI:

    * ``chat_progress_chunks`` — OpenAI Chat Completions ``chat.completion.chunk``.
    * ``responses_progress_events`` — OpenAI Responses API event dicts.

Key entry points:
    ``chat_progress_chunks``, ``responses_progress_events``.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from typing import Any

from auditor.progress import (
    ProgressEvent,
    args_for_stream,
    format_requirement_label,
)


def _chat_chunk(
    model: str,
    completion_id: str,
    *,
    delta: dict[str, Any],
    finish: str | None = None,
) -> str:
    """Format one OpenAI chat-completion SSE ``data:`` line.

    Args:
        model: Model id advertised to the client (e.g. ``auditor``).
        completion_id: Unique completion id for this response.
        delta: Partial message delta (``content``, ``tool_calls``, etc.).
        finish: Optional ``finish_reason`` when the stream ends.

    Returns:
        A complete SSE frame: ``data: {json}\\n\\n``.
    """
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
    """Convert one progress event into OpenAI chat-completion SSE chunks.

    Handles ``reasoning``, ``phase``, ``req_status``, ``tool_call``, and
    ``tool_result`` event kinds. Reasoning text is sent both as
    ``reasoning_content`` (for capable clients) and italicized ``content``.

    Args:
        event: Internal progress event from the audit graph.
        model: Model id for the SSE payload.
        completion_id: Completion id for the SSE payload.
        tool_index: Zero-based index for parallel tool-call deltas.

    Returns:
        List of SSE frame strings (may be empty for unhandled kinds).
    """
    out: list[str] = []
    if event.kind in ("reasoning", "phase", "req_status"):
        text = event.text or ""
        if event.kind == "req_status" and event.requirement_id:
            req_label = format_requirement_label(
                event.requirement_id, event.requirement_title
            )
            text = text or f"`{req_label}` → {event.status}"
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
        req_label = format_requirement_label(
            event.requirement_id, event.requirement_title
        )
        out.append(
            _chat_chunk(
                model,
                completion_id,
                delta={
                    "content": (
                        f"\n**{label}**"
                        + (f" (`{req_label}`)" if req_label else "")
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
    """Convert one progress event into OpenAI Responses API event dicts.

    Mirrors ``chat_progress_chunks`` but emits Responses-native event types
    (``response.reasoning_summary_text.delta``, ``response.output_text.delta``,
    function-call argument deltas, etc.) for newer Open WebUI connections.

    Args:
        event: Internal progress event from the audit graph.
        response_id: Responses API id (``resp_…``).
        seq_fn: Callable returning the next monotonic ``sequence_number``.
        message_id: Assistant message item id within the response.

    Returns:
        List of event dicts to JSON-encode as SSE ``data:`` payloads.
    """
    events: list[dict[str, Any]] = []
    if event.kind in ("reasoning", "phase", "req_status"):
        text = event.text or ""
        if event.kind == "req_status" and event.requirement_id:
            req_label = format_requirement_label(
                event.requirement_id, event.requirement_title
            )
            text = text or f"`{req_label}` → {event.status}"
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
        req_label = format_requirement_label(
            event.requirement_id, event.requirement_title
        )
        events.append(
            {
                "type": "response.output_text.delta",
                "item_id": message_id,
                "output_index": 0,
                "content_index": 0,
                "delta": (
                    f"\n**{label}**"
                    + (f" (`{req_label}`)" if req_label else "")
                    + f" →\n```\n{preview}\n```\n"
                ),
                "sequence_number": seq_fn(),
            }
        )
        return events

    return events


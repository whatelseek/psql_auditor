"""OpenAI-compatible ``/v1`` endpoints for Open WebUI.

Open WebUI connects to this service as if it were an OpenAI (or LiteLLM) chat
backend. Two endpoints matter:

* ``GET /v1/models`` — advertises ``Settings.model_id`` (default ``psql-auditor``)
* ``POST /v1/chat/completions`` — runs the LangGraph audit and returns the report

When ``stream=true``, the handler emits Server-Sent Events (SSE) in OpenAI
chunk format, narrating tool starts and then streaming the final report.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from langchain_core.messages import AIMessage, HumanMessage
from pydantic import BaseModel

from psql_auditor.config import get_settings
from psql_auditor.graph import get_auditor_graph

router = APIRouter(prefix="/v1")


class ChatMessage(BaseModel):
    """Single message in an OpenAI chat-completions request.

    Attributes:
        role: OpenAI role (``system`` / ``user`` / ``assistant`` / ``tool``).
        content: Message text; may be empty for some tool roles.
    """

    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = ""


class ChatCompletionRequest(BaseModel):
    """Subset of the OpenAI chat-completions request body we accept.

    Attributes:
        model: Requested model id (defaults to ``Settings.model_id``).
        messages: Conversation history from Open WebUI.
        stream: When true, respond with SSE chunks instead of a single JSON body.
        temperature: Accepted for compatibility; audit graph uses temp=0 internally.
        user: Optional end-user identifier from the client (unused for now).
    """

    model: str | None = None
    messages: list[ChatMessage]
    stream: bool = False
    temperature: float | None = None
    user: str | None = None


def _check_api_key(authorization: str | None) -> None:
    """Validate the optional Bearer token against ``Settings.api_key``.

    If ``API_KEY`` is unset, authentication is skipped (convenient for local
    Compose). When set, requests must send ``Authorization: Bearer <key>``.

    Args:
        authorization: Raw ``Authorization`` header value, if any.

    Raises:
        HTTPException: 401 when a key is required but missing/invalid.
    """
    settings = get_settings()
    if not settings.api_key:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    if token != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _latest_user_text(messages: list[ChatMessage]) -> str:
    """Extract the operator prompt that kicks off an audit run.

    Prefers the latest ``user`` message. If none is present, concatenates
    user/system contents, and finally falls back to a default audit instruction.

    Args:
        messages: Chat history from the client.

    Returns:
        Non-empty string used as ``user_request`` for the graph.
    """
    for msg in reversed(messages):
        if msg.role == "user" and msg.content:
            return msg.content
    parts = [m.content or "" for m in messages if m.role in ("user", "system")]
    return "\n".join(p for p in parts if p).strip() or "Run a full PostgreSQL security audit."


def _completion_payload(content: str, model: str, completion_id: str) -> dict[str, Any]:
    """Build a non-streaming OpenAI ``chat.completion`` response body.

    Args:
        content: Final assistant text (audit summary + report).
        model: Model id echoed back to the client.
        completion_id: Unique completion id (``chatcmpl-…``).

    Returns:
        Dict matching the OpenAI chat.completion schema (usage left at zeros).
    """
    return {
        "id": completion_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _sse_chunk(
    content: str | None,
    model: str,
    completion_id: str,
    finish: str | None = None,
) -> str:
    """Serialize one OpenAI SSE ``chat.completion.chunk`` line.

    Special cases:

    * ``content is None`` and ``finish is None`` → role-only delta (stream open)
    * ``finish="stop"`` → terminal chunk with empty delta

    Args:
        content: Text to append to the assistant stream, or ``None``.
        model: Model id for the chunk payload.
        completion_id: Shared id across all chunks of this completion.
        finish: Optional OpenAI ``finish_reason`` (usually ``stop``).

    Returns:
        A ``data: {json}\\n\\n`` SSE frame string.
    """
    payload = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"content": content} if content is not None else {},
                "finish_reason": finish,
            }
        ],
    }
    if content is None and finish is None:
        payload["choices"][0]["delta"] = {"role": "assistant"}
    return f"data: {json.dumps(payload)}\n\n"


@router.get("/models")
async def list_models(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """List models advertised to Open WebUI.

    Returns a single synthetic model whose id is ``Settings.model_id``. Open
    WebUI uses this list to populate the model picker.

    Args:
        authorization: Optional Bearer token for API key checks.

    Returns:
        OpenAI-style ``{"object": "list", "data": [...]}`` payload.
    """
    _check_api_key(authorization)
    settings = get_settings()
    return {
        "object": "list",
        "data": [
            {
                "id": settings.model_id,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "psql-auditor",
            }
        ],
    }


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Run a full checklist audit and return the report as a chat completion.

    Non-streaming path calls ``AuditorGraph.arun`` and wraps the ``report`` in a
    standard OpenAI JSON response. Streaming path yields SSE progress (tool
    starts) plus the final report via ``_stream_audit``.

    Args:
        body: OpenAI chat-completions request from Open WebUI.
        request: FastAPI request (reserved for future middleware use).
        authorization: Optional Bearer token for API key checks.

    Returns:
        ``JSONResponse`` or ``StreamingResponse`` depending on ``body.stream``.
    """
    _check_api_key(authorization)
    settings = get_settings()
    model = body.model or settings.model_id
    user_text = _latest_user_text(body.messages)
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    auditor = get_auditor_graph()

    if body.stream:
        return StreamingResponse(
            _stream_audit(auditor, user_text, model, completion_id),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    result = await auditor.arun(user_text)
    content = result.get("report") or _last_ai_text(result.get("messages") or [])
    return JSONResponse(_completion_payload(content, model, completion_id))


def _last_ai_text(messages: list) -> str:
    """Fallback: find the last assistant message if ``report`` is missing.

    Args:
        messages: LangGraph message list from the final state.

    Returns:
        Assistant text, or a short placeholder string.
    """
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            return str(msg.content)
    return "Audit completed with no report content."


async def _stream_audit(
    auditor,
    user_text: str,
    model: str,
    completion_id: str,
) -> AsyncIterator[str]:
    """Stream an audit run as OpenAI-compatible SSE chunks.

    Uses LangGraph ``astream_events(version="v2")`` to observe tool starts and
    capture the finalize node's ``report``. Emits:

    1. Role-open chunk
    2. Status line ("Starting…")
    3. Tool narration lines as tools begin
    4. Final report in ~400-character chunks
    5. ``finish_reason=stop`` chunk and ``[DONE]``

    Args:
        auditor: ``AuditorGraph`` instance whose compiled ``graph`` is streamed.
        user_text: Operator prompt seeding the run.
        model: Model id echoed in each chunk.
        completion_id: Shared completion id for this stream.

    Yields:
        SSE frame strings ready to write to the HTTP response body.
    """
    yield _sse_chunk(None, model, completion_id)
    yield _sse_chunk(
        "Starting PostgreSQL checklist audit…\n\n",
        model,
        completion_id,
    )

    initial: dict[str, Any] = {
        "messages": [HumanMessage(content=user_text)],
        "user_request": user_text,
    }

    final_report = ""
    try:
        async for event in auditor.graph.astream_events(initial, version="v2"):
            kind = event.get("event")
            name = event.get("name") or ""
            data = event.get("data") or {}

            if kind == "on_tool_start":
                # Narrate tool use so Open WebUI shows progress during long audits.
                tool_input = data.get("input")
                preview = json.dumps(tool_input, default=str)[:120]
                yield _sse_chunk(
                    f"Tool `{name}`… {preview}\n",
                    model,
                    completion_id,
                )
            elif kind == "on_chain_end" and name == "finalize":
                output = data.get("output") or {}
                if isinstance(output, dict) and output.get("report"):
                    final_report = output["report"]
            elif kind == "on_chain_end" and name == "LangGraph":
                # Fallback: some LangGraph versions only emit the outer end event.
                output = data.get("output") or {}
                if isinstance(output, dict) and output.get("report"):
                    final_report = output["report"]
    except Exception as exc:  # noqa: BLE001 — surface failure in the stream
        yield _sse_chunk(f"\n\nAudit error: {exc}\n", model, completion_id)
        yield _sse_chunk(None, model, completion_id, finish="stop")
        yield "data: [DONE]\n\n"
        return

    if final_report:
        # Chunk the report for smoother UI rendering on long outputs.
        chunk_size = 400
        for i in range(0, len(final_report), chunk_size):
            yield _sse_chunk(final_report[i : i + chunk_size], model, completion_id)
    else:
        yield _sse_chunk(
            "\nAudit finished (no report captured).\n",
            model,
            completion_id,
        )

    yield _sse_chunk(None, model, completion_id, finish="stop")
    yield "data: [DONE]\n\n"

"""OpenAI-compatible ``/v1`` endpoints for Open WebUI.

Open WebUI connects to this service as if it were an OpenAI (or LiteLLM) chat
backend. Two endpoints matter:

* ``GET /v1/models`` — advertises ``Settings.model_id`` (default ``auditor``)
* ``POST /v1/chat/completions`` — runs the LangGraph audit and returns the report
* ``POST /v1/responses`` — thin OpenAI Responses API shim (newer Open WebUI)

Human-in-the-loop: when a requirement fails, the graph interrupts and the
assistant asks **skip** / **retry**. The next user message resumes the same
thread (marker ``[AUDIT_HITL:<thread_id>]``), similar to the Open WebUI ↔
LangGraph pipe pattern.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from langchain_core.messages import AIMessage
from pydantic import BaseModel

from auditor.config import get_settings
from auditor.graph import get_auditor_graph
from auditor.hitl import extract_hitl_thread_id
from auditor.intake import extract_intake_thread_id
from auditor.intent import classify_intent
from auditor.report_archive import archive_filename, verify_download_token

router = APIRouter(prefix="/v1")


class ChatMessage(BaseModel):
    """Single message in an OpenAI chat-completions request."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = ""


class ChatCompletionRequest(BaseModel):
    """Subset of the OpenAI chat-completions request body we accept."""

    model: str | None = None
    messages: list[ChatMessage]
    stream: bool = False
    temperature: float | None = None
    user: str | None = None


class ResponsesRequest(BaseModel):
    """Minimal OpenAI Responses API request (Open WebUI ``api_type=responses``)."""

    model: str | None = None
    input: Any = None
    instructions: str | None = None
    stream: bool = False
    temperature: float | None = None
    user: str | None = None
    max_output_tokens: int | None = None


def _text_from_content_parts(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                if part.get("type") in {"input_text", "output_text", "text"}:
                    parts.append(str(part.get("text") or ""))
                elif "text" in part:
                    parts.append(str(part.get("text") or ""))
        return "\n".join(p for p in parts if p)
    return str(content)


def _messages_from_responses_input(
    payload: ResponsesRequest,
) -> list[ChatMessage]:
    """Convert Responses ``input`` (+ optional instructions) to chat messages."""
    messages: list[ChatMessage] = []
    if payload.instructions:
        messages.append(ChatMessage(role="system", content=payload.instructions))

    raw = payload.input
    if isinstance(raw, str):
        messages.append(ChatMessage(role="user", content=raw))
        return messages

    if not isinstance(raw, list):
        return messages

    for item in raw:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type") or "message"
        if item_type != "message":
            continue
        role = item.get("role") or "user"
        if role not in ("system", "user", "assistant", "tool"):
            role = "user"
        text = _text_from_content_parts(item.get("content"))
        if text:
            messages.append(ChatMessage(role=role, content=text))  # type: ignore[arg-type]
    return messages


def _responses_payload(content: str, model: str, response_id: str) -> dict[str, Any]:
    message_id = f"msg_{uuid.uuid4().hex[:20]}"
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "model": model,
        "status": "completed",
        # Convenience field some clients read directly.
        "output_text": content,
        "output": [
            {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": content}],
            }
        ],
        "usage": {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
    }


def _sse_responses_event(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


async def _stream_responses_audit(
    auditor,
    body: ChatCompletionRequest,
    model: str,
    response_id: str,
) -> AsyncIterator[str]:
    """Emit OpenAI Responses SSE events (Open WebUI stream=true path)."""
    seq = 0
    message_id = f"msg_{uuid.uuid4().hex[:20]}"
    created_at = int(time.time())

    def _next() -> int:
        nonlocal seq
        seq += 1
        return seq

    empty = _responses_payload("", model, response_id)
    empty["status"] = "in_progress"
    empty["created_at"] = created_at
    empty["output"] = []
    empty["output_text"] = ""

    yield _sse_responses_event(
        {
            "type": "response.created",
            "response": empty,
            "sequence_number": _next(),
        }
    )
    yield _sse_responses_event(
        {
            "type": "response.in_progress",
            "response": empty,
            "sequence_number": _next(),
        }
    )

    # Keep the SSE socket alive while the (often long) audit runs.
    run_task = asyncio.create_task(_run_or_resume(auditor, body))
    while not run_task.done():
        try:
            await asyncio.wait_for(asyncio.shield(run_task), timeout=15.0)
        except TimeoutError:
            yield _sse_responses_event(
                {
                    "type": "response.in_progress",
                    "response": empty,
                    "sequence_number": _next(),
                }
            )

    try:
        result = run_task.result()
        content = result.get("report") or _last_ai_text(result.get("messages") or [])
        if result.get("awaiting_intake"):
            prefix = "Paused for intake — reply to continue the questionnaire.\n\n"
            content = f"{prefix}{content}"
        elif result.get("awaiting_hitl"):
            prefix = "Paused for your decision (skip / retry).\n\n"
            content = f"{prefix}{content}"
        if not content:
            content = "Audit finished (no report captured)."
    except Exception as exc:  # noqa: BLE001
        content = f"Audit error: {exc}"

    yield _sse_responses_event(
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "status": "in_progress",
                "content": [],
            },
            "sequence_number": _next(),
        }
    )
    yield _sse_responses_event(
        {
            "type": "response.content_part.added",
            "item_id": message_id,
            "output_index": 0,
            "content_index": 0,
            "part": {"type": "output_text", "text": ""},
            "sequence_number": _next(),
        }
    )

    chunk_size = 400
    for i in range(0, len(content), chunk_size):
        delta = content[i : i + chunk_size]
        yield _sse_responses_event(
            {
                "type": "response.output_text.delta",
                "item_id": message_id,
                "output_index": 0,
                "content_index": 0,
                "delta": delta,
                "sequence_number": _next(),
            }
        )

    yield _sse_responses_event(
        {
            "type": "response.output_text.done",
            "item_id": message_id,
            "output_index": 0,
            "content_index": 0,
            "text": content,
            "sequence_number": _next(),
        }
    )
    yield _sse_responses_event(
        {
            "type": "response.content_part.done",
            "item_id": message_id,
            "output_index": 0,
            "content_index": 0,
            "part": {"type": "output_text", "text": content},
            "sequence_number": _next(),
        }
    )
    yield _sse_responses_event(
        {
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": content}],
            },
            "sequence_number": _next(),
        }
    )

    final = _responses_payload(content, model, response_id)
    final["created_at"] = created_at
    final["output"][0]["id"] = message_id
    yield _sse_responses_event(
        {
            "type": "response.completed",
            "response": final,
            "sequence_number": _next(),
        }
    )


def _check_api_key(authorization: str | None) -> None:
    settings = get_settings()
    if not settings.api_key:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    if token != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _latest_user_text(messages: list[ChatMessage]) -> str:
    for msg in reversed(messages):
        if msg.role == "user" and msg.content:
            return msg.content
    parts = [m.content or "" for m in messages if m.role in ("user", "system")]
    return "\n".join(p for p in parts if p).strip() or "Run a full PostgreSQL security audit."


def _completion_payload(content: str, model: str, completion_id: str) -> dict[str, Any]:
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
    _check_api_key(authorization)
    settings = get_settings()
    return {
        "object": "list",
        "data": [
            {
                "id": settings.model_id,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "auditor",
            }
        ],
    }


_DOWNLOAD_NAME = re.compile(
    r"^(?P<run_id>.+)_audit\.zip$",
    re.IGNORECASE,
)


@router.get("/downloads/{filename}")
async def download_archive(
    filename: str,
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
):
    """Download a packaged audit zip (report + per-REQ evidence).

    Auth: valid ``?token=`` (for Open WebUI markdown links) **or** Bearer API key.
    """
    settings = get_settings()
    match = _DOWNLOAD_NAME.match(filename)
    if not match:
        raise HTTPException(status_code=404, detail="Unknown archive name")
    run_id = match.group("run_id")
    secret = settings.api_key or "auditor-dev"
    token_ok = verify_download_token(run_id, token, secret)
    bearer_ok = False
    if settings.api_key and authorization and authorization.startswith("Bearer "):
        bearer_ok = authorization.removeprefix("Bearer ").strip() == settings.api_key
    elif not settings.api_key:
        bearer_ok = True
    if not (token_ok or bearer_ok):
        raise HTTPException(status_code=401, detail="Invalid download token")

    zip_path = Path(settings.evidence_dir) / archive_filename(run_id)
    if not zip_path.is_file():
        # Fallback: zip still inside run dir naming convention.
        alt = Path(settings.evidence_dir) / run_id / archive_filename(run_id)
        zip_path = alt if alt.is_file() else zip_path
    if not zip_path.is_file():
        raise HTTPException(status_code=404, detail="Archive not found")

    return FileResponse(
        path=zip_path,
        media_type="application/zip",
        filename=archive_filename(run_id),
        content_disposition_type="attachment",
    )


async def _run_or_resume(auditor, body: ChatCompletionRequest) -> dict[str, Any]:
    """Start audit, follow-up, ad-hoc command run, or resume intake/HITL."""
    user_text = _latest_user_text(body.messages)
    intake_thread = extract_intake_thread_id(body.messages)
    if intake_thread:
        return await auditor.aresume(intake_thread, user_text)
    hitl_thread = extract_hitl_thread_id(body.messages)
    if hitl_thread:
        return await auditor.aresume(hitl_thread, user_text)

    thread_id = None
    if body.user:
        thread_id = f"user-{body.user}"

    settings = get_settings()
    intent = classify_intent(user_text, agents_dir=settings.agents_dir)
    if intent == "revise_req":
        return await auditor.arun_revise_req(
            user_text, messages=body.messages, thread_id=thread_id
        )
    if intent == "refill_finding":
        return await auditor.arun_refill_finding(
            user_text, messages=body.messages, thread_id=thread_id
        )
    if intent == "update_report":
        return await auditor.arun_update_report(
            user_text, messages=body.messages, thread_id=thread_id
        )
    if settings.adhoc_commands_enabled and intent == "adhoc":
        return await auditor.arun_adhoc(user_text, thread_id=thread_id)

    return await auditor.arun(user_text, thread_id=thread_id)


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Run or resume a checklist audit (or ad-hoc commands) as a chat completion."""
    _check_api_key(authorization)
    settings = get_settings()
    model = body.model or settings.model_id
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    auditor = get_auditor_graph()

    if body.stream:
        return StreamingResponse(
            _stream_audit(auditor, body, model, completion_id),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    result = await _run_or_resume(auditor, body)
    content = result.get("report") or _last_ai_text(result.get("messages") or [])
    return JSONResponse(_completion_payload(content, model, completion_id))


@router.post("/responses")
async def responses_api(
    body: ResponsesRequest,
    authorization: str | None = Header(default=None),
):
    """OpenAI Responses API shim used by newer Open WebUI connections.

    Converts ``input`` → chat messages, runs the same audit path as
    ``/v1/chat/completions``. When ``stream=true`` (Open WebUI default),
    emits Responses SSE events so the chat UI receives text.
    """
    _check_api_key(authorization)
    settings = get_settings()
    model = body.model or settings.model_id
    messages = _messages_from_responses_input(body)
    if not messages:
        raise HTTPException(status_code=400, detail="Responses input is empty")

    chat_body = ChatCompletionRequest(
        model=model,
        messages=messages,
        stream=False,
        temperature=body.temperature,
        user=body.user,
    )
    auditor = get_auditor_graph()
    response_id = f"resp_{uuid.uuid4().hex[:24]}"

    if body.stream:
        return StreamingResponse(
            _stream_responses_audit(auditor, chat_body, model, response_id),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    result = await _run_or_resume(auditor, chat_body)
    content = result.get("report") or _last_ai_text(result.get("messages") or [])
    if result.get("awaiting_intake"):
        content = (
            "Paused for intake — reply to continue the questionnaire.\n\n"
            f"{content}"
        )
    elif result.get("awaiting_hitl"):
        content = f"Paused for your decision (skip / retry).\n\n{content}"
    if not content:
        content = "Audit finished (no report captured)."
    return JSONResponse(_responses_payload(content, model, response_id))


def _last_ai_text(messages: list) -> str:
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            return str(msg.content)
    return "Audit completed with no report content."


async def _stream_audit(
    auditor,
    body: ChatCompletionRequest,
    model: str,
    completion_id: str,
) -> AsyncIterator[str]:
    """Stream an audit (or intake/HITL resume) as OpenAI-compatible SSE chunks."""
    settings = get_settings()
    user_text = _latest_user_text(body.messages)
    intake_thread = extract_intake_thread_id(body.messages)
    hitl_thread = extract_hitl_thread_id(body.messages)

    yield _sse_chunk(None, model, completion_id)
    intent = classify_intent(user_text, agents_dir=settings.agents_dir)
    if intake_thread:
        yield _sse_chunk(
            f"Continuing pre-audit intake (`{intake_thread}`)…\n\n",
            model,
            completion_id,
        )
    elif hitl_thread:
        yield _sse_chunk(
            f"Resuming paused audit (`{hitl_thread}`)…\n\n",
            model,
            completion_id,
        )
    elif intent == "revise_req":
        yield _sse_chunk(
            "Collecting more evidence into the prior audit folder…\n\n",
            model,
            completion_id,
        )
    elif intent == "refill_finding":
        yield _sse_chunk(
            "Preparing new observation / recommendation from stored evidence…\n\n",
            model,
            completion_id,
        )
    elif intent == "update_report":
        yield _sse_chunk(
            "Updating report from collected evidence…\n\n",
            model,
            completion_id,
        )
    elif settings.adhoc_commands_enabled and intent == "adhoc":
        yield _sse_chunk(
            "Running ad-hoc audit command(s)…\n\n",
            model,
            completion_id,
        )
    elif settings.intake_enabled:
        # Do not announce frameworks before intake finishes.
        yield _sse_chunk(
            "Starting pre-audit intake…\n\n",
            model,
            completion_id,
        )
    else:
        from auditor.frameworks import route_frameworks

        try:
            selected = route_frameworks(user_text, settings.agents_dir)
            names = ", ".join(f"`{fw.id}`" for fw in selected)
            yield _sse_chunk(
                f"Starting audit for {len(selected)} framework(s): {names} "
                f"(REQ workers={settings.max_parallel_assessments}; "
                f"HITL={'on' if settings.hitl_enabled else 'off'})…\n\n",
                model,
                completion_id,
            )
        except Exception as exc:  # noqa: BLE001
            yield _sse_chunk(f"Routing error: {exc}\n", model, completion_id)
            yield _sse_chunk(None, model, completion_id, finish="stop")
            yield "data: [DONE]\n\n"
            return

    try:
        result = await _run_or_resume(auditor, body)
        final_report = result.get("report") or ""
        if result.get("awaiting_intake") or (
            result.get("awaiting_hitl")
            and "[AUDIT_INTAKE:" in (final_report or "")
        ):
            yield _sse_chunk(
                "Paused for intake — reply to continue the questionnaire.\n\n",
                model,
                completion_id,
            )
        elif result.get("awaiting_hitl"):
            yield _sse_chunk(
                "Paused for your decision (skip / retry).\n\n",
                model,
                completion_id,
            )
        elif result.get("archive_url"):
            yield _sse_chunk(
                "Packaging audit ZIP for download…\n\n",
                model,
                completion_id,
            )
    except Exception as exc:  # noqa: BLE001
        yield _sse_chunk(f"\n\nAudit error: {exc}\n", model, completion_id)
        yield _sse_chunk(None, model, completion_id, finish="stop")
        yield "data: [DONE]\n\n"
        return

    if final_report:
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

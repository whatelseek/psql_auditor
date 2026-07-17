"""OpenAI-compatible ``/v1`` endpoints for Open WebUI.

Open WebUI connects to this service as if it were an OpenAI (or LiteLLM) chat
backend. Two endpoints matter:

* ``GET /v1/models`` — advertises ``Settings.model_id`` (default ``psql-auditor``)
* ``POST /v1/chat/completions`` — runs the LangGraph audit and returns the report

Human-in-the-loop: when a requirement fails, the graph interrupts and the
assistant asks **skip** / **retry**. The next user message resumes the same
thread (marker ``[AUDIT_HITL:<thread_id>]``), similar to the Open WebUI ↔
LangGraph pipe pattern.
"""

from __future__ import annotations

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

from psql_auditor.config import get_settings
from psql_auditor.graph import get_auditor_graph
from psql_auditor.hitl import extract_hitl_thread_id
from psql_auditor.language import detect_response_language, ui
from psql_auditor.report_archive import archive_filename, verify_download_token

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
                "owned_by": "psql-auditor",
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
    secret = settings.api_key or "psql-auditor-dev"
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
    """Start a new audit or resume a HITL-paused thread from chat history."""
    user_text = _latest_user_text(body.messages)
    hitl_thread = extract_hitl_thread_id(body.messages)
    if hitl_thread:
        return await auditor.aresume(hitl_thread, user_text)

    thread_id = None
    if body.user:
        thread_id = f"user-{body.user}"
    return await auditor.arun(user_text, thread_id=thread_id)


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Run or resume a checklist audit as a chat completion."""
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
    """Stream an audit (or HITL resume) as OpenAI-compatible SSE chunks."""
    from psql_auditor.frameworks import route_frameworks

    settings = get_settings()
    user_text = _latest_user_text(body.messages)
    hitl_thread = extract_hitl_thread_id(body.messages)
    lang = detect_response_language(
        user_text,
        default=settings.default_response_language,
    )

    yield _sse_chunk(None, model, completion_id)
    if hitl_thread:
        yield _sse_chunk(
            ui(lang, "stream_resume", thread=hitl_thread),
            model,
            completion_id,
        )
    else:
        try:
            selected = route_frameworks(user_text, settings.agents_dir)
            names = ", ".join(f"`{fw.id}`" for fw in selected)
            yield _sse_chunk(
                ui(
                    lang,
                    "stream_start",
                    count=len(selected),
                    names=names,
                    workers=settings.max_parallel_assessments,
                    hitl="on" if settings.hitl_enabled else "off",
                ),
                model,
                completion_id,
            )
        except Exception as exc:  # noqa: BLE001
            yield _sse_chunk(
                ui(lang, "stream_route_err", exc=exc),
                model,
                completion_id,
            )
            yield _sse_chunk(None, model, completion_id, finish="stop")
            yield "data: [DONE]\n\n"
            return

    try:
        result = await _run_or_resume(auditor, body)
        final_report = result.get("report") or ""
        if result.get("response_language"):
            from psql_auditor.language import language_from_code

            lang = language_from_code(
                str(result.get("response_language")),
                default=settings.default_response_language,
            )
        if result.get("awaiting_hitl"):
            yield _sse_chunk(ui(lang, "stream_hitl"), model, completion_id)
        elif result.get("archive_url"):
            yield _sse_chunk(ui(lang, "stream_zip"), model, completion_id)
    except Exception as exc:  # noqa: BLE001
        yield _sse_chunk(
            ui(lang, "stream_audit_err", exc=exc),
            model,
            completion_id,
        )
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

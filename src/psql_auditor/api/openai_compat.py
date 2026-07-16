"""OpenAI-compatible /v1 endpoints for Open WebUI."""

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
    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = ""


class ChatCompletionRequest(BaseModel):
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
    # Fallback: concatenate all user/system content
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


def _sse_chunk(content: str | None, model: str, completion_id: str, finish: str | None = None) -> str:
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
async def list_models(authorization: str | None = Header(default=None)) -> dict[str, Any]:
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
                tool_input = data.get("input")
                preview = json.dumps(tool_input, default=str)[:120]
                yield _sse_chunk(
                    f"🔧 Tool `{name}`… {preview}\n",
                    model,
                    completion_id,
                )
            elif kind == "on_chain_end" and name == "finalize":
                output = data.get("output") or {}
                if isinstance(output, dict) and output.get("report"):
                    final_report = output["report"]
            elif kind == "on_chain_end" and name == "LangGraph":
                output = data.get("output") or {}
                if isinstance(output, dict) and output.get("report"):
                    final_report = output["report"]
    except Exception as exc:  # noqa: BLE001
        yield _sse_chunk(f"\n\nAudit error: {exc}\n", model, completion_id)
        yield _sse_chunk(None, model, completion_id, finish="stop")
        yield "data: [DONE]\n\n"
        return

    if final_report:
        # Stream report in chunks for nicer UI
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

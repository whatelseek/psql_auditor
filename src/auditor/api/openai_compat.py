"""OpenAI-compatible ``/v1`` endpoints for Open WebUI.

Open WebUI connects to this service as if it were an OpenAI (or LiteLLM) chat
backend. This module is the **HTTP adapter** between chat UI requests and
``auditor.graph.AuditorGraph``.

Endpoints:
    * ``GET /v1/models`` — Advertises ``Settings.model_id`` (default ``auditor``).
    * ``POST /v1/chat/completions`` — Runs or resumes the LangGraph audit; supports SSE.
    * ``POST /v1/responses`` — Thin OpenAI Responses API shim (newer Open WebUI).
    * ``GET /v1/downloads/{filename}`` — Signed download links for audit ZIP archives.

Human-in-the-loop:
    When a requirement fails, the graph interrupts and the assistant asks
    **skip** / **retry**. The next user message resumes the same thread
    (marker ``[AUDIT_HITL:<thread_id>]``), similar to the Open WebUI ↔
    LangGraph pipe pattern.

Key entry points:
    ``router``, ``chat_completions``, ``responses_api``, ``list_models``,
    ``download_archive``.
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
from auditor.graph import get_auditor_graph_ready
from auditor.hitl import is_continue_reply, resolve_pause_resume
from auditor.intent import classify_intent
from auditor.progress import ProgressSink, bind_progress_sink
from auditor.api.stream_progress import (
    chat_progress_chunks,
    responses_progress_events,
)
from auditor.report_archive import archive_filename, verify_download_token
from auditor.results_store import (
    parse_continue_session_request,
    resolve_continue_target,
)

router = APIRouter(prefix="/v1")


class ChatMessage(BaseModel):
    """Single message in an OpenAI chat-completions request body.

    Attributes:
        role: Message author — ``system``, ``user``, ``assistant``, or ``tool``.
        content: Plain-text body; may be empty for tool-call-only assistant turns.
    """

    role: str = "user"
    content: str | None = ""


class ChatCompletionRequest(BaseModel):
    """Subset of the OpenAI chat-completions request body accepted by the auditor.

    Attributes:
        model: Optional model override; defaults to ``Settings.model_id``.
        messages: Full conversation history (used for resume markers and context).
        stream: When ``True``, return Server-Sent Events instead of one JSON body.
        temperature: Accepted for compatibility; not passed to the audit graph.
        user: Optional stable user id; used to derive a persistent ``thread_id``.
    """

    model: str | None = None
    messages: list[ChatMessage]
    stream: bool = False
    temperature: float | None = None
    user: str | None = None


class ResponsesRequest(BaseModel):
    """Minimal OpenAI Responses API request (Open WebUI ``api_type=responses``).

    Attributes:
        model: Optional model override.
        input: String user message or list of structured input items.
        instructions: Optional system prompt prepended as a system message.
        stream: When ``True``, emit Responses SSE events during the audit.
        temperature: Accepted for compatibility; ignored by the graph.
        user: Optional stable user id for thread derivation.
        max_output_tokens: Accepted for compatibility; not enforced.
    """

    model: str | None = None
    input: Any = None
    instructions: str | None = None
    stream: bool = False
    temperature: float | None = None
    user: str | None = None
    max_output_tokens: int | None = None


def _text_from_content_parts(content: Any) -> str:
    """Flatten OpenAI-style multipart content into a single string.

    Handles plain strings, lists of strings, and dict parts with ``type`` in
    ``input_text``, ``output_text``, or ``text``.

    Args:
        content: Raw ``content`` field from a Responses API input item.

    Returns:
        Joined text with newlines, or ``""`` for ``None``.
    """
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
    """Convert Responses ``input`` (+ optional instructions) to chat messages.

    Args:
        payload: Parsed Responses API request.

    Returns:
        Chat messages suitable for ``ChatCompletionRequest``; may be empty
        when ``input`` is missing or unparseable.
    """
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
    """Build a completed OpenAI Responses API response object.

    Args:
        content: Final assistant text (report or pause message).
        model: Model id echoed in the response.
        response_id: Unique response id (``resp_…``).

    Returns:
        Dict matching the Responses API ``response`` shape with ``output_text``
        convenience field and zeroed token usage.
    """
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
    """Encode one Responses API event as an SSE ``data:`` frame.

    Args:
        payload: Event dict (must be JSON-serializable).

    Returns:
        ``data: {json}\\n\\n`` string for ``StreamingResponse``.
    """
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


async def _stream_responses_audit(
    auditor,
    body: ChatCompletionRequest,
    model: str,
    response_id: str,
) -> AsyncIterator[str]:
    """Emit OpenAI Responses SSE events while an audit runs (``stream=true``).

    Binds a ``ProgressSink``, shields the audit task from client disconnect,
    streams progress as Responses events, then emits the final report in
    ``response.output_text.delta`` chunks.

    Args:
        auditor: Ready ``AuditorGraph`` instance.
        body: Normalized chat request (messages from Responses input).
        model: Model id for all SSE payloads.
        response_id: Responses API id for this run.

    Yields:
        SSE frame strings (``data: …\\n\\n``).
    """
    seq = 0
    message_id = f"msg_{uuid.uuid4().hex[:20]}"
    created_at = int(time.time())
    progress_q: asyncio.Queue[Any] = asyncio.Queue()

    def _next() -> int:
        """Return the next monotonic Responses API ``sequence_number``."""
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

    sink = ProgressSink()

    async def _runner() -> dict[str, Any]:
        """Run audit with progress sink bound (Responses stream path)."""
        with bind_progress_sink(sink):
            try:
                return await _run_or_resume(auditor, body)
            finally:
                sink.close()

    run_task = asyncio.create_task(_runner())
    # Shield so client disconnect does not cancel the audit mid-assess.
    shielded = asyncio.ensure_future(asyncio.shield(run_task))

    async def _pump_progress() -> None:
        """Move progress events from the sink queue into the async output queue."""
        while True:
            event = await sink.queue.get()
            await progress_q.put(event)
            if event is None:
                break

    pump = asyncio.create_task(_pump_progress())

    content = ""
    try:
        while True:
            if shielded.done() and progress_q.empty():
                # Drain any last events
                pass
            try:
                event = await asyncio.wait_for(progress_q.get(), timeout=15.0)
            except TimeoutError:
                yield _sse_responses_event(
                    {
                        "type": "response.in_progress",
                        "response": empty,
                        "sequence_number": _next(),
                    }
                )
                if shielded.done() and progress_q.empty():
                    break
                continue
            if event is None:
                break
            for ev in responses_progress_events(
                event,
                response_id=response_id,
                seq_fn=_next,
                message_id=message_id,
            ):
                yield _sse_responses_event(ev)

        await pump
        result = await shielded
        content = result.get("report") or _last_ai_text(result.get("messages") or [])
        if result.get("awaiting_intake"):
            content = (
                "Paused for intake — reply to continue the questionnaire.\n\n"
                + (content or "")
            )
        elif result.get("awaiting_hitl"):
            content = (
                "Paused for your decision (skip / retry).\n\n" + (content or "")
            )
        if not content:
            content = "Audit finished (no report captured)."
    except Exception as exc:  # noqa: BLE001
        if not run_task.done():
            # Keep orphan running for continue-from-checkpoint
            tid = ""
            try:
                # best-effort: leave task in auditor orphan map if thread known later
                pass
            except Exception:  # noqa: BLE001
                pass
        content = f"Audit error: {exc}"

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
    """Validate Bearer token when ``Settings.api_key`` is configured.

    Args:
        authorization: Raw ``Authorization`` header value.

    Raises:
        HTTPException: 401 when a key is required but missing or incorrect.
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
    """Extract the most recent non-empty user message from the conversation.

    Falls back to concatenated user/system content, then a default audit prompt.

    Args:
        messages: Conversation history from the chat request.

    Returns:
        Text to classify as audit intent and pass to the graph.
    """
    for msg in reversed(messages):
        if msg.role == "user" and msg.content:
            return msg.content
    parts = [m.content or "" for m in messages if m.role in ("user", "system")]
    return "\n".join(p for p in parts if p).strip() or "Run a full PostgreSQL security audit."


def _completion_payload(content: str, model: str, completion_id: str) -> dict[str, Any]:
    """Build a non-streaming OpenAI chat-completion response object.

    Args:
        content: Assistant message body (audit report or pause text).
        model: Model id echoed in the response.
        completion_id: Unique completion id (``chatcmpl-…``).

    Returns:
        Dict matching the Chat Completions API response schema.
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
    """Format one OpenAI chat-completion SSE chunk.

    Args:
        content: Partial assistant text, or ``None`` for role-only or finish chunks.
        model: Model id for the chunk.
        completion_id: Completion id for the chunk.
        finish: Optional ``finish_reason`` (e.g. ``stop``).

    Returns:
        SSE frame: ``data: {json}\\n\\n``.
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
    """List the single auditor model advertised to Open WebUI.

    Args:
        authorization: Optional Bearer token when API key auth is enabled.

    Returns:
        OpenAI-style model list with one entry (``Settings.model_id``).
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
    """Download a packaged audit ZIP (report + per-REQ evidence).

    Auth: valid ``?token=`` query parameter (for Open WebUI markdown links)
    **or** Bearer API key matching ``Settings.api_key``.

    Args:
        filename: Must match ``{run_id}_audit.zip`` (case-insensitive).
        authorization: Optional Bearer token.
        token: HMAC download token embedded in chat archive links.

    Returns:
        ``FileResponse`` streaming the ZIP attachment.

    Raises:
        HTTPException: 404 for unknown names or missing files; 401 for bad auth.
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
    """Start audit, follow-up, ad-hoc command run, or resume intake/HITL/continue.

    Classifies the latest user message via ``classify_intent`` and dispatches
    to the appropriate ``AuditorGraph`` method. Pause/resume markers in the
    message history take precedence over intent routing.

    Args:
        auditor: Ready ``AuditorGraph`` instance.
        body: Parsed chat-completions request.

    Returns:
        Graph result dict with ``report``, ``messages``, and optional pause flags.
    """
    user_text = _latest_user_text(body.messages)
    settings = get_settings()

    # Explicit ``continue session N for Client`` must win over stale
    # ``[AUDIT_INTAKE|/HITL]`` markers still present in Open WebUI history —
    # otherwise resume starts intake again and allocates a new warehouse session.
    session_num, client_hint = parse_continue_session_request(user_text)
    explicit_continue = session_num is not None and bool(client_hint)
    if is_continue_reply(user_text) or explicit_continue:
        target = await resolve_continue_target(settings, user_text)
        if target:
            tid, run_id, _sess = target
            return await auditor.acontinue(tid, run_id=run_id)
        if explicit_continue:
            slug = (client_hint or "client").strip().lower().replace(" ", "_")
            return {
                "report": (
                    f"Could not resume session **#{session_num}** for "
                    f"**{client_hint}**.\n\n"
                    f"Try `List audit sessions for {client_hint}` and ensure "
                    f"`artifacts/{slug}/` still exists."
                ),
                "awaiting_hitl": False,
                "messages": [],
            }

    paused = resolve_pause_resume(body.messages)
    if paused:
        kind, thread_id = paused
        if kind == "continue":
            return await auditor.acontinue(thread_id)
        return await auditor.aresume(thread_id, user_text)

    thread_id = None
    if body.user:
        thread_id = f"user-{body.user}"

    intent = classify_intent(user_text, agents_dir=settings.agents_dir)
    if intent == "list_results":
        return await auditor.alist_results(user_text)
    if intent == "list_sessions":
        return await auditor.alist_sessions(user_text)
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
    """Run or resume a checklist audit (or ad-hoc commands) as a chat completion.

    Args:
        body: Chat request including messages and optional ``stream`` flag.
        request: Raw FastAPI request (reserved for future disconnect handling).
        authorization: Optional Bearer API key.

    Returns:
        ``JSONResponse`` with the full report, or ``StreamingResponse`` (SSE)
        when ``body.stream`` is ``True``.
    """
    _check_api_key(authorization)
    settings = get_settings()
    model = body.model or settings.model_id
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    auditor = await get_auditor_graph_ready()

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
    emits Responses SSE events so the chat UI receives incremental text.

    Args:
        body: Responses API request (``input``, ``instructions``, ``stream``).
        authorization: Optional Bearer API key.

    Returns:
        Completed response JSON or ``StreamingResponse`` for SSE streaming.

    Raises:
        HTTPException: 400 when ``input`` yields no messages.
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
    auditor = await get_auditor_graph_ready()
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
    """Return content of the last ``AIMessage`` in a LangChain message list.

    Args:
        messages: LangChain message objects from graph state.

    Returns:
        String content of the most recent assistant message, or a fallback
        when no AI content is present.
    """
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
    """Stream an audit (or intake/HITL resume) as OpenAI-compatible SSE chunks.

    Emits an initial role chunk, a human-readable preamble based on intent,
    progress events via ``chat_progress_chunks``, then the final report in
    fixed-size content deltas.

    Args:
        auditor: Ready ``AuditorGraph`` instance.
        body: Chat request with conversation history.
        model: Model id for all SSE payloads.
        completion_id: Completion id for all SSE payloads.

    Yields:
        SSE frame strings ending with ``data: [DONE]\\n\\n``.
    """
    settings = get_settings()
    user_text = _latest_user_text(body.messages)
    paused = resolve_pause_resume(body.messages)
    session_num, client_hint = parse_continue_session_request(user_text)
    explicit_continue = session_num is not None and bool(client_hint)

    yield _sse_chunk(None, model, completion_id)
    intent = classify_intent(user_text, agents_dir=settings.agents_dir)
    if is_continue_reply(user_text) or explicit_continue:
        label = (
            f"session #{session_num} for {client_hint}"
            if explicit_continue
            else "interrupted audit"
        )
        yield _sse_chunk(
            f"Continuing {label} from checkpoint…\n\n",
            model,
            completion_id,
        )
    elif paused and paused[0] == "intake":
        yield _sse_chunk(
            f"Continuing pre-audit intake (`{paused[1]}`)…\n\n",
            model,
            completion_id,
        )
    elif paused and paused[0] == "hitl":
        yield _sse_chunk(
            f"Resuming paused audit (`{paused[1]}`)…\n\n",
            model,
            completion_id,
        )
    elif paused and paused[0] == "continue":
        yield _sse_chunk(
            f"Continuing interrupted audit (`{paused[1]}`)…\n\n",
            model,
            completion_id,
        )
    elif intent == "list_results":
        yield _sse_chunk(
            "Loading warehouse REQ results for the requested session…\n\n",
            model,
            completion_id,
        )
    elif intent == "list_sessions":
        yield _sse_chunk(
            "Looking up audit sessions in the results warehouse…\n\n",
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

    sink = ProgressSink()
    progress_q: asyncio.Queue[Any] = asyncio.Queue()
    tool_index = 0

    async def _runner() -> dict[str, Any]:
        """Run audit with progress sink bound (chat completions stream path)."""
        with bind_progress_sink(sink):
            try:
                return await _run_or_resume(auditor, body)
            finally:
                sink.close()

    run_task = asyncio.create_task(_runner())
    shielded = asyncio.ensure_future(asyncio.shield(run_task))

    async def _pump() -> None:
        """Move progress events from the sink queue into the async output queue."""
        while True:
            event = await sink.queue.get()
            await progress_q.put(event)
            if event is None:
                break

    pump = asyncio.create_task(_pump())
    final_report = ""

    try:
        while True:
            try:
                event = await asyncio.wait_for(progress_q.get(), timeout=15.0)
            except TimeoutError:
                # Keepalive whitespace so proxies don't idle-out.
                yield _sse_chunk(" ", model, completion_id)
                if shielded.done() and progress_q.empty():
                    break
                continue
            if event is None:
                break
            nonlocal_chunks = chat_progress_chunks(
                event,
                model=model,
                completion_id=completion_id,
                tool_index=tool_index,
            )
            if event.kind == "tool_call":
                tool_index += 1
            for chunk in nonlocal_chunks:
                yield chunk

        await pump
        result = await shielded
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

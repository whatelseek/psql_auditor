"""OWUI slash/list intents must win over stale intake/HITL chat markers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from auditor.api.openai_compat import ChatCompletionRequest, _run_or_resume_once


@pytest.mark.asyncio
async def test_list_sessions_wins_over_stale_intake_marker(monkeypatch):
    auditor = MagicMock()
    auditor.alist_sessions = AsyncMock(return_value={"report": "ok", "messages": []})
    auditor.aresume = AsyncMock(return_value={"report": "wrong", "messages": []})
    auditor.arun = AsyncMock(return_value={"report": "wrong", "messages": []})

    settings = MagicMock()
    settings.agents_dir = "agents"
    settings.adhoc_commands_enabled = True
    runtime = MagicMock()
    runtime.settings = settings

    body = ChatCompletionRequest(
        messages=[
            {
                "role": "assistant",
                "content": (
                    "What is the client name?\n"
                    "[AUDIT_INTAKE:audit-abc:intake]\n"
                    "_Paused for intake._"
                ),
            },
            {"role": "user", "content": "List audit sessions"},
        ]
    )

    result = await _run_or_resume_once(runtime, auditor, body, settings=settings)
    assert result["report"] == "ok"
    auditor.alist_sessions.assert_awaited_once_with("List audit sessions")
    auditor.aresume.assert_not_awaited()


@pytest.mark.asyncio
async def test_plain_intake_answer_still_resumes(monkeypatch):
    auditor = MagicMock()
    auditor.aresume = AsyncMock(return_value={"report": "resumed", "messages": []})
    auditor.alist_sessions = AsyncMock()
    auditor.arun = AsyncMock()

    settings = MagicMock()
    settings.agents_dir = "agents"
    settings.adhoc_commands_enabled = True
    runtime = MagicMock()
    runtime.settings = settings

    body = ChatCompletionRequest(
        messages=[
            {
                "role": "assistant",
                "content": (
                    "What is the client name?\n"
                    "[AUDIT_INTAKE:audit-abc:intake]\n"
                    "_Paused for intake._"
                ),
            },
            {"role": "user", "content": "testcompany"},
        ]
    )

    result = await _run_or_resume_once(runtime, auditor, body, settings=settings)
    assert result["report"] == "resumed"
    auditor.aresume.assert_awaited_once_with("audit-abc:intake", "testcompany")
    auditor.alist_sessions.assert_not_awaited()


@pytest.mark.asyncio
async def test_open_webui_tag_prompt_does_not_start_audit(monkeypatch):
    """OWUI chat-tag helper must not invoke arun / intake."""
    from auditor.api.openai_compat import ChatCompletionRequest, ChatMessage, _run_or_resume_once
    from auditor.config import Settings

    called = {"arun": 0}

    class _FakeAuditor:
        async def arun(self, *args, **kwargs):
            called["arun"] += 1
            return {"report": "should-not-run"}

    class _FakeRuntime:
        settings = Settings(_env_file=None, intake_enabled=True, adhoc_commands_enabled=False)

    body = ChatCompletionRequest(
        messages=[
            ChatMessage(
                role="user",
                content=(
                    "### Task:\nGenerate 1-3 broad tags categorizing the main "
                    "themes of the chat history...\n\n### Chat History:\n"
                    "<chat_history>\nUSER: hi\n</chat_history>"
                ),
            )
        ]
    )
    result = await _run_or_resume_once(
        _FakeRuntime(),  # type: ignore[arg-type]
        _FakeAuditor(),
        body,
        settings=_FakeRuntime.settings,
    )
    assert called["arun"] == 0
    assert "tags" in (result.get("report") or "").lower()
    assert not result.get("awaiting_intake")

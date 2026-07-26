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
    monkeypatch.setattr("auditor.api.openai_compat.get_settings", lambda: settings)

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

    result = await _run_or_resume_once(auditor, body)
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
    monkeypatch.setattr("auditor.api.openai_compat.get_settings", lambda: settings)

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

    result = await _run_or_resume_once(auditor, body)
    assert result["report"] == "resumed"
    auditor.aresume.assert_awaited_once_with("audit-abc:intake", "testcompany")
    auditor.alist_sessions.assert_not_awaited()

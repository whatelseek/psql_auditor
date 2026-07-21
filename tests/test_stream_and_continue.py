"""Tests for live SSE progress + continue markers."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from langchain_core.messages import AIMessage

from auditor.api.stream_progress import chat_progress_chunks, responses_progress_events
from auditor.config import Settings
from auditor.graph import AuditorGraph
from auditor.hitl import (
    format_continue_assistant_message,
    format_hitl_assistant_message,
    is_continue_reply,
    resolve_pause_resume,
)
from auditor.progress import ProgressEvent
from auditor.session_store import (
    find_interrupted_run,
    load_all_multi_sessions,
    save_multi_session,
    write_run_status,
)


def test_chat_progress_emits_tool_calls():
    ev = ProgressEvent(
        kind="tool_call",
        tool_name="ssh_run",
        tool_call_id="call_abc",
        arguments={"command": "id"},
        requirement_id="REQ-001",
    )
    chunks = chat_progress_chunks(
        ev, model="auditor", completion_id="cmpl_1", tool_index=0
    )
    assert chunks
    payload = json.loads(chunks[0].removeprefix("data: ").strip())
    tc = payload["choices"][0]["delta"]["tool_calls"][0]
    assert tc["function"]["name"] == "ssh_run"
    assert "id" in tc


def test_chat_progress_emits_reasoning():
    ev = ProgressEvent(kind="reasoning", text="Planning REQ-001")
    chunks = chat_progress_chunks(
        ev, model="auditor", completion_id="cmpl_1", tool_index=0
    )
    joined = "".join(chunks)
    assert "reasoning_content" in joined or "Planning REQ-001" in joined


def test_responses_progress_function_call():
    seq = {"n": 0}

    def _next() -> int:
        seq["n"] += 1
        return seq["n"]

    ev = ProgressEvent(
        kind="tool_call",
        tool_name="mcp_query",
        tool_call_id="fc_1",
        arguments={"sql": "select 1"},
    )
    events = responses_progress_events(
        ev, response_id="resp_1", seq_fn=_next, message_id="msg_1"
    )
    types = [e["type"] for e in events]
    assert "response.output_item.added" in types
    assert "response.function_call_arguments.delta" in types


def test_resolve_continue_marker():
    messages = [
        {
            "role": "assistant",
            "content": format_hitl_assistant_message("x", "audit-1:intake"),
        },
        {
            "role": "assistant",
            "content": format_continue_assistant_message("paused", "audit-1:host:postgres_cis"),
        },
        {"role": "user", "content": "continue"},
    ]
    assert resolve_pause_resume(messages) == (
        "continue",
        "audit-1:host:postgres_cis",
    )
    assert is_continue_reply("продолжи пожалуйста")


def test_session_store_roundtrip(tmp_path: Path):
    run_id = "TestRun"
    (tmp_path / run_id).mkdir()
    save_multi_session(
        tmp_path,
        run_id,
        "tid-1",
        {"run_id": run_id, "remaining": ["ubuntu_cis"], "ssh_target": None},
    )
    loaded = load_all_multi_sessions(tmp_path, run_id)
    assert "tid-1" in loaded
    write_run_status(
        tmp_path,
        run_id,
        status="interrupted",
        thread_id="tid-1",
        pending_ids=["REQ-002"],
        framework_id="postgres_cis",
    )
    found = find_interrupted_run(tmp_path)
    assert found is not None
    assert found[0] == run_id
    assert found[1]["status"] == "interrupted"


@pytest.mark.asyncio
async def test_sqlite_checkpointer_survives_new_graph(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        agents_dir=Path("agents"),
        evidence_dir=tmp_path / "artifacts",
        checkpoint_path=tmp_path / "cp" / "auditor.sqlite",
        max_session_retries=0,
        hitl_enabled=True,
        max_parallel_assessments=2,
        memory_enabled=False,
        intake_enabled=False,
        archive_enabled=False,
    )
    graph = AuditorGraph(settings=settings)
    await graph.ensure_async_checkpointer()

    async def fake_fill(req_id, requirement, user_request, framework_id="", store=None, **kwargs):
        from auditor.state import Finding

        return Finding(
            requirement_id=req_id,
            title=requirement.title,
            status="error",
            severity=requirement.severity,
            category=requirement.category,
            pass_criteria=requirement.pass_criteria,
            evidence=f"SSH error: cannot audit {req_id}",
            remediation="Check SSH",
        )

    mock_llm = AsyncMock()
    mock_llm.ainvoke = AsyncMock(return_value=AIMessage(content="skip_all"))
    with (
        patch.object(graph, "_fill_requirement_cells", side_effect=fake_fill),
        patch.object(graph, "fill_model", mock_llm),
        patch.object(graph, "collect_host_facts", AsyncMock(return_value={})),
    ):
        paused = await graph.arun_one(
            "Audit PostgreSQL CIS",
            framework_id="postgres_cis",
            thread_id="test-durable-pg",
        )
        assert paused.get("awaiting_hitl") is True

    # Flush / close so the second process sees durable rows.
    cm = getattr(graph, "_sqlite_cm", None)
    if cm is not None:
        await cm.__aexit__(None, None, None)
        graph._sqlite_cm = None
        graph._async_cp_ready = False

    assert (tmp_path / "cp" / "auditor.sqlite").is_file()

    graph2 = AuditorGraph(settings=settings)
    await graph2.ensure_async_checkpointer()
    assert type(graph2._checkpointer).__name__ == "AsyncSqliteSaver"
    snap = await graph2.graph.aget_state({"configurable": {"thread_id": "test-durable-pg"}})
    assert snap.values.get("framework_id") == "postgres_cis"
    assert snap.tasks or snap.next

    with (
        patch.object(graph2, "fill_model", mock_llm),
        patch.object(graph2, "_fill_requirement_cells", side_effect=fake_fill),
        patch.object(graph2, "collect_host_facts", AsyncMock(return_value={})),
    ):
        resumed = await graph2.aresume("test-durable-pg", "skip all")
        for _ in range(40):
            if not resumed.get("awaiting_hitl"):
                break
            resumed = await graph2.aresume("test-durable-pg", "skip all")

    assert resumed.get("awaiting_hitl") is False
    report = resumed.get("report") or ""
    assert "Audit Report" in report or "Framework:" in report or "skipped" in report.lower()

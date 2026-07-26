"""Tests for ad-hoc command execution (playbook path without live SSH)."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from auditor.adhoc import run_adhoc_commands
from auditor.config import Settings
from auditor.graph import AuditorGraph


@pytest.mark.asyncio
async def test_adhoc_playbook_executes_seed_tools(tmp_path: Path):
    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path / "artifacts",
        memory_enabled=True,
        memory_learn=False,
        adhoc_commands_enabled=True,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)

    async def fake_execute(tool_calls, **kwargs):
        return [
            ToolMessage(
                content="PermitRootLogin no",
                tool_call_id=tc.get("id") or "x",
                name=tc.get("name") or "ssh_run",
            )
            for tc in tool_calls
        ]

    graph._execute_tool_calls = fake_execute  # type: ignore[method-assign]
    graph.fill_model = MagicMock()
    graph.fill_model.ainvoke = AsyncMock(
        return_value=AIMessage(content="Root login disabled (`PermitRootLogin no`).")
    )

    result = await run_adhoc_commands(
        graph,
        "Run playbook commands for REQ-002 on Ubuntu CIS",
    )
    assert result["adhoc"] is True
    assert result["mode"] == "playbook"
    assert "Ad-hoc command results" in result["report"]
    assert "PermitRootLogin" in result["report"] or "Root login" in result["report"]


@pytest.mark.asyncio
async def test_adhoc_freeform_uses_tool_loop(tmp_path: Path):
    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path / "artifacts",
        memory_enabled=True,
        memory_learn=False,
        adhoc_commands_enabled=True,
        max_tool_rounds_per_item=2,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)

    tool_response = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "ssh_run",
                "args": {"command": "uptime"},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )
    final_response = AIMessage(content="Host uptime looks healthy.")

    graph.evidence_model = MagicMock()
    graph.evidence_model.ainvoke = AsyncMock(side_effect=[tool_response, final_response])
    graph._execute_tool_calls = AsyncMock(  # type: ignore[method-assign]
        return_value=[ToolMessage(content="up 3 days", tool_call_id="call-1", name="ssh_run")]
    )

    result = await run_adhoc_commands(graph, "Run this command: `uptime`")
    assert result["adhoc"] is True
    assert result["mode"] == "freeform"
    assert "uptime" in result["report"].lower() or "healthy" in result["report"].lower()
    graph._execute_tool_calls.assert_awaited()

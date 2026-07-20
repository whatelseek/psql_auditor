from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from langchain_core.messages import AIMessage

from auditor.checklist import Requirement
from auditor.config import Settings
from auditor.graph import AuditorGraph, _hitl_candidates
from auditor.hitl import (
    build_hitl_prompt,
    extract_hitl_thread_id,
    format_hitl_assistant_message,
    parse_hitl_decision,
)
from auditor.state import Finding


def test_parse_hitl_decision_variants():
    assert parse_hitl_decision("skip").action == "skip"
    assert parse_hitl_decision("Please retry").action == "retry"
    assert parse_hitl_decision("skip all").action == "skip_all"
    assert parse_hitl_decision("retry all failed checks").action == "retry_all"
    assert parse_hitl_decision("maybe later").action == "unknown"


def test_extract_hitl_thread_id_from_history():
    messages = [
        {"role": "assistant", "content": "hello"},
        {
            "role": "assistant",
            "content": format_hitl_assistant_message("prompt", "audit-abc:ubuntu_cis"),
        },
        {"role": "user", "content": "skip"},
    ]
    assert extract_hitl_thread_id(messages) == "audit-abc:ubuntu_cis"


def test_build_hitl_prompt_includes_why_and_options():
    req = Requirement(
        id="REQ-001",
        title="SSH root login",
        how_to_verify="Read sshd_config",
        pass_criteria="PermitRootLogin no",
    )
    finding = Finding(
        requirement_id="REQ-001",
        title=req.title,
        status="error",
        evidence="SSH error: Connection refused",
        remediation="Fix SSH_HOST",
    )
    text = build_hitl_prompt(
        framework_id="ubuntu_cis",
        requirement=req,
        finding=finding,
    )
    assert "Could not audit" in text
    assert "Connection refused" in text
    assert "skip" in text.lower()
    assert "retry" in text.lower()


def test_hitl_candidates_excludes_skipped():
    state = {
        "findings": {
            "REQ-001": Finding(requirement_id="REQ-001", status="error", evidence="x"),
            "REQ-002": Finding(requirement_id="REQ-002", status="pass", evidence="ok"),
            "REQ-003": Finding(requirement_id="REQ-003", status="error", evidence="y"),
        },
        "hitl_skipped": ["REQ-001"],
    }
    assert _hitl_candidates(state) == ["REQ-003"]


def test_route_after_assess_goes_to_human_gate():
    settings = Settings(
        _env_file=None,
        agents_dir=Path("agents"),
        max_session_retries=0,
        hitl_enabled=True,
    )
    graph = AuditorGraph(settings=settings)
    state = {
        "pending_ids": [],
        "retry_count": 0,
        "findings": {
            "REQ-001": Finding(
                requirement_id="REQ-001",
                status="error",
                evidence="SSH error: boom",
            )
        },
        "hitl_skipped": [],
    }
    assert graph.route_after_assess(state) == "human_gate"
    settings_off = Settings(
        _env_file=None,
        agents_dir=Path("agents"),
        hitl_enabled=False,
    )
    graph_off = AuditorGraph(settings=settings_off)
    assert graph_off.route_after_assess(state) == "finalize"


@pytest.mark.asyncio
async def test_hitl_skip_then_finalize(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        agents_dir=Path("agents"),
        evidence_dir=tmp_path,
        max_session_retries=0,
        hitl_enabled=True,
        max_parallel_assessments=2,
    )
    graph = AuditorGraph(settings=settings)

    async def fake_fill(req_id, requirement, user_request, framework_id="", store=None):
        return Finding(
            requirement_id=req_id,
            title=requirement.title,
            status="error",
            severity=requirement.severity,
            category=requirement.category,
            pass_criteria=requirement.pass_criteria,
            evidence=f"SSH error: cannot audit {req_id}",
            remediation="Check SSH connectivity",
        )

    mock_llm = AsyncMock()
    mock_llm.ainvoke = AsyncMock(
        return_value=AIMessage(content="Executive summary OK.")
    )
    with (
        patch.object(graph, "_fill_requirement_cells", side_effect=fake_fill),
        patch.object(graph, "fill_model", mock_llm),
    ):
        paused = await graph.arun_one(
            "Audit Ubuntu CIS",
            framework_id="ubuntu_cis",
            thread_id="test-hitl-ubuntu",
        )

        assert paused.get("awaiting_hitl") is True
        assert "Could not audit" in (paused.get("report") or "")
        assert "[AUDIT_HITL:test-hitl-ubuntu]" in (paused.get("report") or "")

        # Skip all remaining failures in one HITL reply.
        resumed = await graph.aresume("test-hitl-ubuntu", "skip all")

    assert resumed.get("awaiting_hitl") is False
    report = resumed.get("report") or ""
    assert "Audit Report" in report or "Framework:" in report
    assert "skipped" in report.lower()

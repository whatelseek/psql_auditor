from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from auditor.context import (
    compact_findings_for_summary,
    count_tool_rounds,
    truncate_text,
    truncate_tool_messages,
)
from auditor.state import Finding


def test_truncate_text_adds_marker():
    text = "a" * 100
    out = truncate_text(text, 50, "output")
    assert len(out) < 100
    assert "truncated" in out


def test_truncate_tool_messages():
    messages = [
        HumanMessage(content="hi"),
        ToolMessage(content="x" * 500, tool_call_id="1"),
    ]
    out = truncate_tool_messages(messages, 80)
    assert isinstance(out[1], ToolMessage)
    assert len(str(out[1].content)) < 200
    assert "truncated" in str(out[1].content)


def test_count_tool_rounds():
    messages = [
        AIMessage(content="", tool_calls=[{"name": "mcp_query", "args": {}, "id": "1"}]),
        ToolMessage(content="ok", tool_call_id="1"),
        AIMessage(content="", tool_calls=[{"name": "ssh_run", "args": {}, "id": "2"}]),
    ]
    assert count_tool_rounds(messages) == 2


def test_compact_findings_digest():
    findings = {
        "REQ-002": Finding(
            requirement_id="REQ-002",
            title="SSL",
            status="fail",
            severity="High",
            evidence="ssl=off " + ("detail " * 100),
        ),
        "REQ-001": Finding(
            requirement_id="REQ-001",
            title="Auth",
            status="pass",
            severity="High",
            evidence="scram-sha-256",
        ),
    }
    digest = compact_findings_for_summary(findings, evidence_chars=40)
    assert "REQ-001" in digest
    assert "REQ-002" in digest
    assert "fail" in digest
    assert len(digest) < 2000

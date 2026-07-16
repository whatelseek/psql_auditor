"""LangGraph state and finding models."""

from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel

from psql_auditor.checklist import Requirement


FindingStatus = Literal["pass", "fail", "partial", "error", "skipped"]


class Finding(BaseModel):
    requirement_id: str
    title: str = ""
    status: FindingStatus
    severity: str = ""
    category: str = ""
    evidence: str = ""
    remediation: str = ""
    notes: str = ""


def merge_findings(
    left: dict[str, Finding] | None,
    right: dict[str, Finding] | None,
) -> dict[str, Finding]:
    merged = dict(left or {})
    merged.update(right or {})
    return merged


class AuditorState(TypedDict, total=False):
    messages: Annotated[list[BaseMessage], add_messages]
    user_request: str
    checklist_title: str
    requirements: dict[str, Requirement]
    pending_ids: list[str]
    current_id: str | None
    findings: Annotated[dict[str, Finding], merge_findings]
    report: str
    error: str | None
    target_hints: dict[str, Any]


def aggregate_findings(findings: dict[str, Finding]) -> dict[str, int]:
    counts: dict[str, int] = {
        "pass": 0,
        "fail": 0,
        "partial": 0,
        "error": 0,
        "skipped": 0,
    }
    for finding in findings.values():
        status = finding.status if isinstance(finding, Finding) else finding["status"]
        counts[status] = counts.get(status, 0) + 1
    return counts


def render_report(
    checklist_title: str,
    findings: dict[str, Finding],
    requirements: dict[str, Requirement] | None = None,
) -> str:
    counts = aggregate_findings(findings)
    total = sum(counts.values())
    lines = [
        f"# Audit Report: {checklist_title}",
        "",
        f"Assessed **{total}** requirements — "
        f"pass: {counts['pass']}, fail: {counts['fail']}, "
        f"partial: {counts['partial']}, error: {counts['error']}, "
        f"skipped: {counts['skipped']}.",
        "",
    ]

    order = list(requirements.keys()) if requirements else sorted(findings.keys())
    for req_id in order:
        finding = findings.get(req_id)
        if finding is None:
            continue
        if not isinstance(finding, Finding):
            finding = Finding.model_validate(finding)
        title = finding.title or (
            requirements[req_id].title if requirements and req_id in requirements else ""
        )
        lines.append(f"## {req_id}: {title}")
        lines.append(f"- **Status:** {finding.status}")
        if finding.severity:
            lines.append(f"- **Severity:** {finding.severity}")
        if finding.category:
            lines.append(f"- **Category:** {finding.category}")
        if finding.evidence:
            lines.append(f"- **Evidence:** {finding.evidence}")
        if finding.remediation:
            lines.append(f"- **Remediation:** {finding.remediation}")
        if finding.notes:
            lines.append(f"- **Notes:** {finding.notes}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"

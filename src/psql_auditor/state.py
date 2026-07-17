"""LangGraph state schema and fixed-format audit report helpers.

The report skeleton is generated from the checklist (fixed cells). The model
only fills ``status``, ``observation`` (stored as ``evidence``), and
``recommendation`` (stored as ``remediation``). Category, severity, title, and
pass criteria always come from the Markdown checklist — never from the LLM.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

from psql_auditor.checklist import Requirement

FindingStatus = Literal["pass", "fail", "partial", "error", "skipped"]


class Finding(BaseModel):
    """Filled cells for one checklist requirement.

    Attributes:
        requirement_id: Checklist id (e.g. ``REQ-001``).
        title / severity / category: Copied from the checklist (fixed).
        status: Model-filled status cell.
        evidence: Model-filled **observation** cell (factual).
        remediation: Model-filled **recommendation** cell.
        notes: Optional extra notes (usually unused in fixed format).
        pass_criteria: Copied from checklist for the fixed report column.
    """

    requirement_id: str
    title: str = ""
    status: FindingStatus
    severity: str = ""
    category: str = ""
    evidence: str = Field(default="", description="Observation cell")
    remediation: str = Field(default="", description="Recommendation cell")
    notes: str = ""
    pass_criteria: str = ""


def merge_findings(
    left: dict[str, Finding] | None,
    right: dict[str, Finding] | None,
) -> dict[str, Finding]:
    """LangGraph reducer: merge two findings dicts."""
    merged = dict(left or {})
    merged.update(right or {})
    return merged


class AuditorState(TypedDict, total=False):
    """Shared state for one audit graph run."""

    messages: Annotated[list[BaseMessage], add_messages]
    user_request: str
    framework_id: str
    framework_title: str
    checklist_title: str
    requirements: dict[str, Requirement]
    pending_ids: list[str]
    current_id: str | None
    findings: Annotated[dict[str, Finding], merge_findings]
    report: str
    error: str | None
    target_hints: dict[str, Any]
    # Cyclic reconnect loop: how many session restores have been attempted.
    retry_count: int
    # Disk artifacts: <evidence_dir>/<run_id>/<framework>/REQ-NNN/
    evidence_run_id: str
    evidence_run_dir: str
    # Human-in-the-loop: requirement ids the operator chose to skip.
    hitl_skipped: list[str]
    # True when the graph is paused waiting for skip/retry.
    awaiting_hitl: bool


def aggregate_findings(findings: dict[str, Finding]) -> dict[str, int]:
    """Count findings by status for the report summary line."""
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


def _md_escape_cell(text: str) -> str:
    """Flatten text for a single Markdown table cell."""
    return " ".join((text or "").replace("|", "/").split())


def render_report(
    checklist_title: str,
    findings: dict[str, Finding],
    requirements: dict[str, Requirement] | None = None,
) -> str:
    """Render the fixed-format Markdown audit report.

    Every checklist requirement appears as a row/section. Fixed fields
    (title, category, severity, pass criteria) come from ``requirements``.
    Model-filled cells are status, observation, recommendation.

    Args:
        checklist_title: Report title.
        findings: Filled cells keyed by requirement id.
        requirements: Full checklist map (defines row order and fixed fields).

    Returns:
        Markdown report with a summary table plus per-requirement detail blocks.
    """
    order = list(requirements.keys()) if requirements else sorted(findings.keys())
    # Ensure skipped rows exist for missing findings when requirements known.
    effective: dict[str, Finding] = {}
    for req_id in order:
        if req_id in findings:
            f = findings[req_id]
            effective[req_id] = f if isinstance(f, Finding) else Finding.model_validate(f)
        elif requirements and req_id in requirements:
            req = requirements[req_id]
            effective[req_id] = Finding(
                requirement_id=req_id,
                title=req.title,
                status="skipped",
                severity=req.severity,
                category=req.category,
                pass_criteria=req.pass_criteria,
                evidence="",
                remediation="",
            )

    counts = aggregate_findings(effective)
    total = len(effective)
    lines = [
        f"# Audit Report: {checklist_title}",
        "",
        "Fixed report format — checklist fields are immutable; the model fills "
        "**Status**, **Observation**, and **Recommendation** only.",
        "",
        f"Assessed **{total}** requirements — "
        f"pass: {counts['pass']}, fail: {counts['fail']}, "
        f"partial: {counts['partial']}, error: {counts['error']}, "
        f"skipped: {counts['skipped']}.",
        "",
        "## Summary table",
        "",
        "| ID | Title | Severity | Status | Observation | Recommendation |",
        "|---|---|---|---|---|---|",
    ]

    for req_id in order:
        f = effective.get(req_id)
        if f is None:
            continue
        req = requirements.get(req_id) if requirements else None
        title = f.title or (req.title if req else "")
        severity = f.severity or (req.severity if req else "")
        lines.append(
            "| "
            + " | ".join(
                [
                    req_id,
                    _md_escape_cell(title),
                    _md_escape_cell(severity),
                    f.status,
                    _md_escape_cell(f.evidence),
                    _md_escape_cell(f.remediation),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Requirement details", ""])

    for req_id in order:
        f = effective.get(req_id)
        if f is None:
            continue
        req = requirements.get(req_id) if requirements else None
        title = f.title or (req.title if req else "")
        category = f.category or (req.category if req else "")
        severity = f.severity or (req.severity if req else "")
        pass_criteria = f.pass_criteria or (req.pass_criteria if req else "")
        how = req.how_to_verify if req else ""

        lines.append(f"### {req_id}: {title}")
        lines.append("")
        lines.append("| Cell | Value |")
        lines.append("|---|---|")
        lines.append(f"| Category | {_md_escape_cell(category)} |")
        lines.append(f"| Severity | {_md_escape_cell(severity)} |")
        lines.append(f"| Pass criteria | {_md_escape_cell(pass_criteria)} |")
        if how:
            lines.append(f"| How to verify | {_md_escape_cell(how)} |")
        lines.append(f"| **Status** | {f.status} |")
        lines.append(f"| **Observation** | {_md_escape_cell(f.evidence)} |")
        lines.append(f"| **Recommendation** | {_md_escape_cell(f.remediation)} |")
        lines.append("")

    return "\n".join(lines).strip() + "\n"

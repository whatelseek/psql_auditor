"""LangGraph state schema and audit finding / report helpers.

``AuditorState`` is the TypedDict passed between LangGraph nodes. Two fields use
reducers so partial node updates merge correctly:

* ``messages`` — LangGraph ``add_messages`` (append / replace by id)
* ``findings`` — ``merge_findings`` (dict union; later keys overwrite)

``Finding`` is the structured outcome of assessing one checklist requirement.
``render_report`` turns the findings map into Markdown for the chat response.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel

from psql_auditor.checklist import Requirement

# Allowed assessment outcomes written by the assess node / LLM JSON.
FindingStatus = Literal["pass", "fail", "partial", "error", "skipped"]


class Finding(BaseModel):
    """Result of assessing a single checklist requirement.

    Attributes:
        requirement_id: Checklist id (e.g. ``REQ-001``).
        title: Requirement title copied for report readability.
        status: Assessment outcome (pass / fail / partial / error / skipped).
        severity: Copied from the checklist for prioritization in the report.
        category: Copied from the checklist for grouping.
        evidence: Factual notes grounded in tool output (or error explanation).
        remediation: Suggested fix when status is not ``pass``.
        notes: Optional clarifications (scope limits, assumptions, etc.).
    """

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
    """LangGraph reducer: merge two findings dicts.

    Nodes typically return ``{"findings": {req_id: Finding(...)}}``. This
    reducer unions that partial update into the accumulated map so earlier
    findings are preserved across the assess loop.

    Args:
        left: Existing findings already in state (may be ``None`` on first write).
        right: Incoming partial findings from the current node.

    Returns:
        A new dict containing all keys from ``left`` overwritten/extended by
        ``right``.
    """
    merged = dict(left or {})
    merged.update(right or {})
    return merged


class AuditorState(TypedDict, total=False):
    """Shared state for one audit graph run.

    All keys are optional (``total=False``) so nodes can return partial updates.
    Callers should still seed ``messages`` / ``user_request`` at invoke time.

    Keys:
        messages: Conversation / tool transcript (append-only via reducer).
        user_request: Original operator prompt from Open WebUI / API.
        checklist_title: Title from the Markdown H1.
        requirements: Map of requirement id → ``Requirement`` objects.
        pending_ids: Remaining requirement ids to assess (queue).
        current_id: Requirement currently under assessment, or ``None``.
        findings: Accumulated ``Finding`` objects keyed by requirement id.
        report: Final Markdown report produced by ``finalize``.
        error: Optional top-level error string for fatal failures.
        target_hints: Reserved for future per-chat host/DSN overrides.
    """

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
    """Count findings by status for the report summary line.

    Args:
        findings: Map of requirement id → ``Finding`` (or dict-shaped findings).

    Returns:
        Dict with keys ``pass``, ``fail``, ``partial``, ``error``, ``skipped``
        and integer counts (missing statuses are zero).
    """
    counts: dict[str, int] = {
        "pass": 0,
        "fail": 0,
        "partial": 0,
        "error": 0,
        "skipped": 0,
    }
    for finding in findings.values():
        # Tolerate plain dicts if state was serialized/deserialized.
        status = finding.status if isinstance(finding, Finding) else finding["status"]
        counts[status] = counts.get(status, 0) + 1
    return counts


def render_report(
    checklist_title: str,
    findings: dict[str, Finding],
    requirements: dict[str, Requirement] | None = None,
) -> str:
    """Render a Markdown audit report from structured findings.

    When ``requirements`` is provided, sections are emitted in checklist order
    (even if findings were recorded out of order). Otherwise findings are sorted
    by requirement id.

    Args:
        checklist_title: Heading used in the report title.
        findings: Completed findings keyed by requirement id.
        requirements: Optional ordered requirement map for section ordering and
            title fallback.

    Returns:
        UTF-8 Markdown string ending with a trailing newline.
    """
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

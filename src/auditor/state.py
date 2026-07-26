"""LangGraph state schema and fixed-format audit report helpers.

Defines the shared :class:`AuditorState` TypedDict consumed by every node in the
audit graph. Canonical assessment data is :class:`~auditor.domain.AssessmentResult`
(CORE-004). :class:`Finding` remains as a **report adapter** that maps
``observation``→``evidence`` and ``recommendation``→``remediation`` for Markdown
output only — it is not a second competing workflow result model.

Category, severity, title, and pass criteria always come from the Markdown
checklist — never from the LLM.

Used after each requirement assessment (findings merge) and at finalize time
when the graph writes ``state["report"]``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

from auditor.checklist import Requirement
from auditor.domain.assessment_result import AssessmentResult
from auditor.domain.result_identity import (
    finding_for_requirement,
    merge_result_maps,
    result_id_of,
)
from auditor.language import ReportLanguage, report_ui

# AUD-003: extended statuses required by canonical fixtures / future EXC work.
# Warehouse and helpers accept the full set; legacy reports still emit ``skipped``.
FindingStatus = Literal[
    "pass",
    "fail",
    "partial",
    "error",
    "skipped",
    "not_tested",
    "not_applicable",
    "accepted_exception",
]


class Finding(BaseModel):
    """Report adapter over :class:`~auditor.domain.AssessmentResult` (CORE-004).

    Prefer constructing :class:`AssessmentResult` in workflow/persistence paths
    and calling :meth:`AssessmentResult.to_finding` for Markdown rendering.
    Legacy field names ``evidence`` / ``remediation`` are report-column labels
    for ``observation`` / ``recommendation`` — not indefinite bidirectional aliases.

    Attributes:
        result_id: Stable UUID for this result (physical identity).
        client_id / audit_run_id / asset_id / framework_id / framework_version:
            Logical uniqueness dimensions (with ``requirement_id``).
        requirement_id: Checklist id (e.g. ``REQ-001``); unique only within a
            framework version — never a global result key.
        title / severity / category: Copied from the checklist (fixed).
        status: Model-filled status cell.
        evidence: Report column for observation (from AssessmentResult.observation).
        remediation: Report column for recommendation.
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
    # CORE-003 canonical identity (mandatory before persistence).
    result_id: str = ""
    client_id: str = ""
    audit_run_id: str = ""
    asset_id: str = ""
    framework_id: str = ""
    framework_version: str = ""


def _coerce_assessment(raw: Any) -> AssessmentResult:
    """Normalize Finding / dict / AssessmentResult to AssessmentResult."""
    if isinstance(raw, AssessmentResult):
        return raw
    if isinstance(raw, Finding):
        return AssessmentResult.from_finding(raw)
    return AssessmentResult.from_finding(raw)


def merge_findings(
    left: dict[str, Finding | AssessmentResult] | None,
    right: dict[str, Finding | AssessmentResult] | None,
) -> dict[str, AssessmentResult]:
    """LangGraph reducer: merge assessment results keyed by ``result_id``.

    Accepts legacy :class:`Finding` values and coerces them to
    :class:`AssessmentResult`. Rejects duplicate ``result_id`` with conflicting
    logical keys and duplicate logical keys with different ``result_id`` values.
    Same ``result_id`` + same logical key allows content updates (correction /
    external validation) without changing identity.
    """
    left_norm = {k: _coerce_assessment(v) for k, v in (left or {}).items()}
    right_norm = {k: _coerce_assessment(v) for k, v in (right or {}).items()}
    merged = merge_result_maps(left_norm, right_norm)
    out: dict[str, AssessmentResult] = {}
    for rid, raw in merged.items():
        result = _coerce_assessment(raw)
        if result_id_of(result) != rid:
            # Rebuild with corrected physical id only when map key disagrees
            # (should be rare); logical dimensions stay intact.
            ident = result.identity.model_copy(update={"result_id": rid})
            result = result.model_copy(update={"identity": ident})
        out[rid] = result
    return out


class AuditorState(TypedDict, total=False):
    """Shared state for one audit graph run.

    All keys are optional at construction time; nodes populate them as the graph
    progresses from intake through assessment to finalize. Message history uses
    LangGraph's ``add_messages`` reducer; findings use :func:`merge_findings`.

    Key fields:
        messages: Chat history for the current graph thread.
        user_request: Original operator prompt.
        report_language: ``en`` or ``ru`` from language detection.
        framework_id / framework_title / checklist_title: Active framework metadata.
        requirements: Parsed checklist map keyed by ``REQ-NNN``.
        pending_ids / current_id: Assessment queue cursor.
        findings: AssessmentResult map keyed by ``result_id`` (not requirement_id).
        report: Final Markdown report string.
        evidence_run_id / evidence_run_dir: On-disk artifact paths.
        intake / intake_complete: Pre-audit questionnaire answers.
        results_session_number: Postgres warehouse session id.
        audit_run_id / asset_id / client_id / framework_version: CORE-003 identity.
        host_facts_md / cmdb_drift_md: Host inventory snapshots.
        archive_path / archive_url: Zip bundle for chat download.
    """

    messages: Annotated[list[BaseMessage], add_messages]
    user_request: str
    # Report language code from detect_report_language (``en`` or ``ru`` only).
    report_language: str
    framework_id: str
    framework_title: str
    checklist_title: str
    requirements: dict[str, Requirement]
    pending_ids: list[str]
    current_id: str | None
    findings: Annotated[dict[str, AssessmentResult], merge_findings]
    report: str
    error: str | None
    # Cyclic reconnect loop: how many session restores have been attempted.
    retry_count: int
    # Disk artifacts: <evidence_dir>/<client_name>/<framework>/REQ-NNN/
    evidence_run_id: str
    evidence_run_dir: str
    # Human-in-the-loop: requirement ids the operator chose to skip.
    hitl_skipped: list[str]
    # True when the graph is paused waiting for skip/retry.
    awaiting_hitl: bool
    # Pre-audit intake answers + flags
    intake_complete: bool
    intake: dict[str, Any]
    client_name: str
    has_cmdb: bool
    has_access: bool
    audit_types: str  # cybersecurity | cis | it | both
    # Results warehouse session (Postgres); allocated once per new audit.
    results_session_number: int
    evidence_host_id: str  # host slug under artifacts/<client>/<host>/
    # CORE-003 identity dimensions for this graph job.
    audit_run_id: str
    asset_id: str
    client_id: str
    framework_version: str
    host_facts_md: str
    cmdb_drift_md: str
    # Zip archive of report + evidence for chat download.
    archive_path: str
    archive_url: str
    # LangGraph thread id (for interrupt / continue markers).
    thread_id: str


def aggregate_findings(
    findings: dict[str, Finding | AssessmentResult] | Mapping[str, Any],
) -> dict[str, int]:
    """Count assessment results by status for the report summary line."""
    from collections.abc import Mapping as MappingABC

    counts: dict[str, int] = {
        "pass": 0,
        "fail": 0,
        "partial": 0,
        "error": 0,
        "skipped": 0,
        "not_tested": 0,
        "not_applicable": 0,
        "accepted_exception": 0,
    }
    for finding in findings.values():
        if isinstance(finding, (Finding, AssessmentResult)):
            status = finding.status
        elif isinstance(finding, MappingABC):
            status = finding["status"]
        else:
            status = getattr(finding, "status", "error")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _md_escape_cell(text: str) -> str:
    """Flatten text for a single Markdown table cell.

    Replaces pipe characters (which would break tables), collapses whitespace,
    and strips leading/trailing space.

    Args:
        text: Raw cell content.

    Returns:
        Single-line safe string for pipe-delimited tables.
    """
    return " ".join((text or "").replace("|", "/").split())


def render_report(
    checklist_title: str,
    findings: Mapping[str, Finding | AssessmentResult],
    requirements: dict[str, Requirement] | None = None,
    *,
    language: str | ReportLanguage | None = None,
) -> str:
    """Render the fixed-format Markdown audit report.

    Every checklist requirement appears as a row/section. Fixed fields
    (title, category, severity, pass criteria) come from ``requirements``.
    Model-filled cells are status, observation, recommendation.

    Args:
        checklist_title: Report title.
        findings: Filled cells keyed by ``result_id`` (requirement_id is a field).
        requirements: Full checklist map (defines row order and fixed fields).
        language: Operator-requested report language (UI chrome localization).

    Returns:
        Markdown report with a summary table plus per-requirement detail blocks.
    """
    ui = report_ui(language)
    if requirements:
        order = list(requirements.keys())
    else:
        order = sorted(
            {
                (
                    f.requirement_id
                    if isinstance(f, (Finding, AssessmentResult))
                    else str(f.get("requirement_id") or "")
                )
                for f in findings.values()
            }
        )
    # Ensure skipped rows exist for missing findings when requirements known.
    # Index by requirement_id only for report row layout (scoped checklist).
    effective: dict[str, Finding] = {}
    for req_id in order:
        matched = finding_for_requirement(findings, req_id)
        if matched is not None:
            if isinstance(matched, Finding):
                effective[req_id] = matched
            elif isinstance(matched, AssessmentResult):
                effective[req_id] = matched.to_finding()
            else:
                effective[req_id] = AssessmentResult.from_finding(matched).to_finding()
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
        ui["fixed_format_note"],
        "",
        f"{ui['assessed']} **{total}** {ui['requirements']} — "
        f"{ui['pass']}: {counts['pass']}, {ui['fail']}: {counts['fail']}, "
        f"{ui['partial']}: {counts['partial']}, {ui['error']}: {counts['error']}, "
        f"{ui['skipped']}: {counts['skipped']}.",
        "",
        f"## {ui['summary_table']}",
        "",
        "| "
        + " | ".join(
            [
                ui["col_id"],
                ui["col_title"],
                ui["col_severity"],
                ui["col_status"],
                ui["col_observation"],
                ui["col_recommendation"],
            ]
        )
        + " |",
        "|---|---|---|---|---|---|",
    ]

    for req_id in order:
        f = effective.get(req_id)
        if f is None:
            continue
        req_meta = requirements.get(req_id) if requirements else None
        title = f.title or (req_meta.title if req_meta else "")
        severity = f.severity or (req_meta.severity if req_meta else "")
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

    lines.extend(["", f"## {ui['requirement_details']}", ""])

    for req_id in order:
        f = effective.get(req_id)
        if f is None:
            continue
        req_detail = requirements.get(req_id) if requirements else None
        title = f.title or (req_detail.title if req_detail else "")
        category = f.category or (req_detail.category if req_detail else "")
        severity = f.severity or (req_detail.severity if req_detail else "")
        pass_criteria = f.pass_criteria or (req_detail.pass_criteria if req_detail else "")
        how = req_detail.how_to_verify if req_detail else ""

        lines.append(f"### {req_id}: {title}")
        lines.append("")
        lines.append(f"| {ui['col_cell']} | {ui['col_value']} |")
        lines.append("|---|---|")
        lines.append(f"| {ui['category']} | {_md_escape_cell(category)} |")
        lines.append(f"| {ui['col_severity']} | {_md_escape_cell(severity)} |")
        lines.append(f"| {ui['pass_criteria']} | {_md_escape_cell(pass_criteria)} |")
        if how:
            lines.append(f"| {ui['how_to_verify']} | {_md_escape_cell(how)} |")
        lines.append(f"| **{ui['status']}** | {f.status} |")
        lines.append(f"| **{ui['observation']}** | {_md_escape_cell(f.evidence)} |")
        lines.append(f"| **{ui['recommendation']}** | {_md_escape_cell(f.remediation)} |")
        lines.append("")

    return "\n".join(lines).strip() + "\n"

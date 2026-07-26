"""Pure helpers shared by workflow nodes (no I/O, no graph imports)."""

from __future__ import annotations

import json
import re
from typing import Any

from auditor.domain.assessment_result import AssessmentResult
from auditor.state import AuditorState, Finding

# Tight markers only — bare "session" / "timeout" / "eof" caused false reconnects.
_RECOVERABLE_MARKERS = (
    "mcp error",
    "mcp reconnect failed",
    "ssh error",
    "winrm error",
    "connection refused",
    "connection reset",
    "broken pipe",
    "not connected",
    "closed resource",
    "connection closed",
)


def _extract_json(text: str) -> dict[str, Any] | None:
    """Parse a JSON object from model output (raw or embedded in prose)."""
    text = text.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def _normalize_status(value: str | None) -> str:
    """Map arbitrary status text to an allowed finding status literal."""
    allowed = {
        "pass",
        "fail",
        "partial",
        "error",
        "skipped",
        "not_tested",
        "not_applicable",
        "accepted_exception",
    }
    status = (value or "error").strip().lower()
    return status if status in allowed else "error"


def _is_recoverable_finding(finding: Finding | AssessmentResult) -> bool:
    """True when a finding looks like a dead session / transport failure."""
    if finding.status != "error":
        return False
    if isinstance(finding, AssessmentResult):
        blob = f"{finding.observation} {finding.notes}".lower()
    else:
        blob = f"{finding.evidence} {finding.notes}".lower()
    return any(marker in blob for marker in _RECOVERABLE_MARKERS)


def _as_finding(value: Finding | AssessmentResult | dict[str, Any]) -> Finding:
    """Coerce graph state values to a report ``Finding`` (adapter)."""
    if isinstance(value, Finding):
        return value
    if isinstance(value, AssessmentResult):
        return value.to_finding()
    return AssessmentResult.from_finding(value).to_finding()


def _as_assessment(value: Finding | AssessmentResult | dict[str, Any]) -> AssessmentResult:
    """Coerce graph state values to canonical AssessmentResult."""
    if isinstance(value, AssessmentResult):
        return value
    return AssessmentResult.from_finding(value)


def _hitl_candidates(state: AuditorState) -> list[str]:
    """Requirement ids with ``status=error`` not yet skipped by the operator."""
    findings = state.get("findings") or {}
    skipped = set(state.get("hitl_skipped") or [])
    out: list[str] = []
    for raw in findings.values():
        finding = _as_finding(raw)
        req_id = finding.requirement_id
        if finding.status == "error" and req_id and req_id not in skipped:
            out.append(req_id)
    return sorted(out)


def _tool_result_looks_failed(text: str) -> bool:
    """True when a tool result string indicates transport/auth failure."""
    lower = (text or "").lower()
    return any(
        marker in lower
        for marker in (
            "ssh error",
            "mcp error",
            "tool error",
            "connection refused",
            "permission denied",
        )
    )

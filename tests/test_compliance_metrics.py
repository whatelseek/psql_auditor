"""Tests for findings → compliance metrics helper (results warehouse)."""

from auditor.compliance import findings_to_compliance_metrics
from auditor.state import Finding


def _finding(req_id: str, status: str, severity: str = "High") -> Finding:
    return Finding(
        requirement_id=req_id,
        title=req_id,
        status=status,  # type: ignore[arg-type]
        severity=severity,
    )


def test_findings_to_compliance_metrics():
    findings = {
        "REQ-001": _finding("REQ-001", "pass"),
        "REQ-002": _finding("REQ-002", "fail", "Critical"),
        "REQ-003": _finding("REQ-003", "partial"),
        "REQ-004": _finding("REQ-004", "skipped", "Low"),
    }
    metrics = findings_to_compliance_metrics(findings)
    assert metrics["pass"] == 1
    assert metrics["fail"] == 1
    assert metrics["partial"] == 1
    assert metrics["skipped"] == 1
    # assessed = 3; score = (1 + 0.5) / 3 = 50%
    assert metrics["assessed"] == 3
    assert metrics["compliance_pct"] == 50.0

from psql_auditor.checklist import Requirement
from psql_auditor.state import Finding, aggregate_findings, render_report


def test_aggregate_findings_counts_statuses():
    findings = {
        "REQ-001": Finding(
            requirement_id="REQ-001", status="pass", title="A"
        ),
        "REQ-002": Finding(
            requirement_id="REQ-002", status="fail", title="B"
        ),
        "REQ-003": Finding(
            requirement_id="REQ-003", status="error", title="C"
        ),
        "REQ-004": Finding(
            requirement_id="REQ-004", status="partial", title="D"
        ),
    }
    counts = aggregate_findings(findings)
    assert counts == {
        "pass": 1,
        "fail": 1,
        "partial": 1,
        "error": 1,
        "skipped": 0,
    }


def test_render_report_includes_ordered_requirements():
    requirements = {
        "REQ-001": Requirement(
            id="REQ-001",
            title="Auth",
            category="Access Control",
            severity="High",
        ),
        "REQ-002": Requirement(
            id="REQ-002",
            title="TLS",
            category="Encryption",
            severity="High",
        ),
    }
    findings = {
        "REQ-002": Finding(
            requirement_id="REQ-002",
            title="TLS",
            status="fail",
            severity="High",
            evidence="ssl=off",
            remediation="Set ssl=on",
        ),
        "REQ-001": Finding(
            requirement_id="REQ-001",
            title="Auth",
            status="pass",
            severity="High",
            evidence="scram-sha-256",
        ),
    }
    report = render_report("Demo Checklist", findings, requirements)
    assert report.index("REQ-001") < report.index("REQ-002")
    assert "ssl=off" in report
    assert "Set ssl=on" in report
    assert "pass: 1" in report
    assert "fail: 1" in report

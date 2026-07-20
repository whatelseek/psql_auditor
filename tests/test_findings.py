from auditor.checklist import Requirement
from auditor.state import Finding, aggregate_findings, render_report


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


def test_render_fixed_report_has_immutable_and_filled_cells():
    requirements = {
        "REQ-001": Requirement(
            id="REQ-001",
            title="Auth",
            category="Access Control",
            severity="High",
            pass_criteria="scram-sha-256",
            how_to_verify="SHOW password_encryption",
        ),
        "REQ-002": Requirement(
            id="REQ-002",
            title="TLS",
            category="Encryption",
            severity="High",
            pass_criteria="ssl is on",
            how_to_verify="SHOW ssl",
        ),
    }
    findings = {
        "REQ-002": Finding(
            requirement_id="REQ-002",
            title="TLS",
            status="fail",
            severity="High",
            category="Encryption",
            pass_criteria="ssl is on",
            evidence="ssl=off",
            remediation="Set ssl=on",
        ),
        "REQ-001": Finding(
            requirement_id="REQ-001",
            title="Auth",
            status="pass",
            severity="High",
            category="Access Control",
            pass_criteria="scram-sha-256",
            evidence="password_encryption=scram-sha-256",
            remediation="",
        ),
    }
    report = render_report("Demo Checklist", findings, requirements)
    assert "Fixed report format" in report
    assert "Summary table" in report
    assert report.index("REQ-001") < report.index("REQ-002")
    assert "**Observation**" in report
    assert "**Recommendation**" in report
    assert "Pass criteria" in report
    assert "ssl=off" in report
    assert "Set ssl=on" in report
    # Checklist field preserved
    assert "scram-sha-256" in report

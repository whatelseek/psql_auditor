from psql_auditor.compliance import (
    compliance_by_severity,
    format_compliance_markdown,
    overall_compliance,
    parse_report_findings,
    render_compliance_bar_chart_svg,
)


SAMPLE = """
# Audit Report: Ubuntu CIS

## Summary table

| ID | Title | Severity | Status | Observation | Recommendation |
|---|---|---|---|---|---|
| REQ-001 | Password hashing | High | pass | SHA512 |  |
| REQ-002 | Root login | Critical | fail | PermitRootLogin yes | Set to no |
| REQ-003 | Firewall | High | partial | ufw inactive | Enable ufw |
| REQ-004 | Chrony | Low | skipped |  |  |
| REQ-005 | AppArmor | Medium | pass | enforcing |  |
"""


def test_parse_summary_table():
    rows = parse_report_findings(SAMPLE)
    assert len(rows) == 5
    assert rows[0].req_id == "REQ-001"
    assert rows[1].severity == "Critical"
    assert rows[1].status == "fail"


def test_compliance_by_severity_percentages():
    rows = parse_report_findings(SAMPLE)
    stats = {s.severity: s for s in compliance_by_severity(rows)}
    # High: pass + partial = 1 + 0.5 over 2 assessed = 75%
    assert stats["High"].percent == 75.0
    assert stats["Critical"].percent == 0.0
    assert stats["Medium"].percent == 100.0
    # Low only skipped → assessed 0 → 0%
    assert stats["Low"].percent == 0.0


def test_overall_compliance():
    rows = parse_report_findings(SAMPLE)
    overall = overall_compliance(rows)
    # assessed = 4 (skip excluded): pass2 + partial0.5 = 2.5 / 4 = 62.5
    assert overall.percent == 62.5


def test_svg_and_markdown_output():
    md = format_compliance_markdown(SAMPLE)
    assert "CIS compliance visualization" in md
    assert "<svg" in md
    assert "Overall" in md
    svg = render_compliance_bar_chart_svg(compliance_by_severity(parse_report_findings(SAMPLE)))
    assert svg.startswith("<svg")

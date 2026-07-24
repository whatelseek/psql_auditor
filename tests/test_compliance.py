from auditor.compliance import (
    compliance_by_severity,
    format_chat_summary_visuals,
    format_compliance_markdown,
    format_severity_line,
    overall_compliance,
    parse_report_findings,
    render_compliance_bar_chart_svg,
    severity_issue_counts,
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
    assert "data:image/svg+xml;base64," in md
    assert "Overall" in md
    svg = render_compliance_bar_chart_svg(compliance_by_severity(parse_report_findings(SAMPLE)))
    assert svg.startswith("<svg")


def test_compliance_markdown_russian():
    md = format_compliance_markdown(SAMPLE, language="ru")
    assert "Визуализация соответствия CIS" in md
    assert "Общий уровень соответствия" in md


def test_severity_line_and_chat_visuals():
    rows = parse_report_findings(SAMPLE)
    counts = severity_issue_counts(rows)
    assert counts["Critical"] == 1
    assert counts["High"] == 1  # partial on High
    assert "High: 1" in format_severity_line(counts)
    assert "Critical: 1" in format_severity_line(counts)
    visuals = format_chat_summary_visuals(
        rows,
        status_counts={
            "pass": 2,
            "fail": 1,
            "partial": 1,
            "error": 0,
            "skipped": 1,
        },
        compliance_pct=62.5,
        hosts=2,
        total=5,
    )
    assert "```mermaid" in visuals
    assert "@@@VIZ-START" in visuals
    assert "@@@VIZ-END" in visuals
    assert "data:image/svg+xml;base64," in visuals

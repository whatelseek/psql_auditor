from pathlib import Path

from auditor.checklist import parse_checklist_markdown

SAMPLE = """# Sample Checklist

Intro text ignored for requirements.

## REQ-001: Authentication method
**Category:** Access Control
**Severity:** High
**How to verify:** Check pg_hba.conf
**Pass criteria:** No trust for remote

## REQ-002: SSL enabled
**Category:** Encryption
**Severity:** Medium
**How to verify:** SHOW ssl
**Pass criteria:** ssl is on
"""


def test_parse_checklist_markdown_extracts_requirements():
    checklist = parse_checklist_markdown(SAMPLE)
    assert checklist.title == "Sample Checklist"
    assert checklist.ids() == ["REQ-001", "REQ-002"]
    first = checklist.requirements[0]
    assert first.title == "Authentication method"
    assert first.category == "Access Control"
    assert first.severity == "High"
    assert "pg_hba" in first.how_to_verify
    assert "trust" in first.pass_criteria
    assert "REQ-001" in first.to_prompt_block()


def test_load_bundled_postgres_cis_checklist():
    path = Path(__file__).resolve().parents[1] / "agents" / "postgres_cis.md"
    # Strip frontmatter for the raw loader used by unit test helpers.
    from auditor.frameworks import _parse_agent_file, load_framework_checklist

    fw = _parse_agent_file(path)
    checklist = load_framework_checklist(fw)
    assert len(checklist.requirements) >= 15
    assert checklist.requirements[0].id.startswith("REQ-")
    assert all(r.title for r in checklist.requirements)
    assert all(r.pass_criteria for r in checklist.requirements)

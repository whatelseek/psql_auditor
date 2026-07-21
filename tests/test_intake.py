"""Unit tests for pre-audit intake parsers and audit-type routing."""

from pathlib import Path

from auditor.intake import (
    client_slug,
    domains_for_audit_type,
    extract_intake_thread_id,
    frameworks_for_audit_type,
    parse_audit_type,
    parse_client_name,
    parse_yes_no,
)


def test_parse_yes_no():
    assert parse_yes_no("yes") == "yes"
    assert parse_yes_no("Да") == "yes"
    assert parse_yes_no("no") == "no"
    assert parse_yes_no("нет") == "no"
    assert parse_yes_no("maybe") == "unknown"


def test_parse_client_and_slug():
    assert parse_client_name("Client: Acme Corp") == "Acme Corp"
    assert client_slug("Acme Corp!") == "acme_corp"


def test_parse_audit_type():
    assert parse_audit_type("Cybersecurity") == "cybersecurity"
    assert parse_audit_type("CIS") == "cybersecurity"
    assert parse_audit_type("IT audit") == "it"
    assert parse_audit_type("both") == "both"
    assert parse_audit_type("CIS + IT") == "both"
    assert parse_audit_type("IT + Cybersecurity") == "both"
    assert parse_audit_type("") is None


def test_domains_for_audit_type():
    assert domains_for_audit_type("it") == ["it"]
    assert domains_for_audit_type("cis") == ["cybersecurity"]
    assert domains_for_audit_type("cybersecurity") == ["cybersecurity"]
    assert domains_for_audit_type("both") == ["it", "cybersecurity"]


def test_extract_intake_marker():
    msgs = [
        {"role": "assistant", "content": "Ask\n[AUDIT_INTAKE:audit-abc:intake]\n"},
        {"role": "user", "content": "Acme"},
    ]
    assert extract_intake_thread_id(msgs) == "audit-abc:intake"


def test_frameworks_for_audit_type_it(tmp_path: Path):
    # Use real agents/ if present
    agents = Path("agents")
    if not (agents / "it_audit.md").is_file():
        return
    assert frameworks_for_audit_type(
        "it", user_request="start it audit", agents_dir=agents
    ) == ["it_audit"]
    both = frameworks_for_audit_type(
        "both", user_request="postgres cis", agents_dir=agents
    )
    assert both[0] == "it_audit"
    assert "it_audit" not in both[1:]

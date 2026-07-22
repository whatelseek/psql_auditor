"""Unit tests for pre-audit intake parsers and audit-type routing."""

from pathlib import Path

from auditor.intake import (
    apply_scope_exclusions,
    client_slug,
    domains_for_audit_type,
    extract_intake_thread_id,
    format_proposed_jobs_markdown,
    frameworks_for_audit_type,
    is_scope_confirm,
    parse_audit_type,
    parse_client_name,
    parse_scope_exclusions,
    parse_yes_no,
    resolve_audit_type,
    resolve_client_name,
    resolve_scope_decision,
    resolve_yes_no,
)


def test_parse_yes_no():
    assert parse_yes_no("yes") == "yes"
    assert parse_yes_no("Да") == "yes"
    assert parse_yes_no("no") == "no"
    assert parse_yes_no("нет") == "no"
    assert parse_yes_no("maybe") == "unknown"
    assert parse_yes_no("nayn") == "unknown"


def test_resolve_yes_no_llm_payload():
    # Typo that regex rejects — LLM JSON wins
    assert resolve_yes_no("nayn", {"answer": "no"}) == "no"
    assert resolve_yes_no("yep!", {"answer": "yes"}) == "yes"
    assert resolve_yes_no("maybe", {"answer": "unknown"}) == "unknown"
    # Regex fallback when no / bad payload
    assert resolve_yes_no("no", None) == "no"
    assert resolve_yes_no("yes", {}) == "yes"
    # LLM unknown but regex clear
    assert resolve_yes_no("no", {"answer": "unknown"}) == "no"


def test_resolve_client_and_audit_type_llm():
    assert resolve_client_name("whatever", {"client_name": "Acme Corp"}) == "Acme Corp"
    assert resolve_client_name("Client: Acme", None) == "Acme"
    assert (
        resolve_audit_type("please do cyber stuff", {"audit_type": "cybersecurity"})
        == "cybersecurity"
    )
    assert resolve_audit_type("both", {"audit_type": None}) == "both"
    assert resolve_audit_type("garbage", {"audit_type": None}) is None


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


def test_scope_confirm_and_exclusions():
    proposed = [
        {
            "host_id": "10_0_0_1",
            "hostname": "pg-db",
            "ssh_host": "10.0.0.1",
            "frameworks": ["it_audit", "postgres_cis", "ubuntu_cis_24_l2"],
        },
        {
            "host_id": "10_0_0_2",
            "hostname": "app",
            "ssh_host": "10.0.0.2",
            "frameworks": ["it_audit", "ubuntu_cis_24_l2"],
        },
    ]
    assert is_scope_confirm("confirm")
    assert is_scope_confirm("все")
    assert is_scope_confirm("run all")

    assert parse_scope_exclusions("confirm", proposed) == (set(), set())
    excl_fw, excl_pairs = parse_scope_exclusions(
        "exclude ubuntu_cis_24_l2, postgres_cis", proposed
    )
    assert excl_fw == {"ubuntu_cis_24_l2", "postgres_cis"}
    assert not excl_pairs

    excl_fw, excl_pairs = parse_scope_exclusions(
        "exclude 10.0.0.1/ubuntu_cis_24_l2", proposed
    )
    assert not excl_fw
    assert ("10.0.0.1", "ubuntu_cis_24_l2") in excl_pairs

    selected = resolve_scope_decision("confirm", proposed)
    assert selected is not None
    assert len(selected) == 2
    assert selected[0]["frameworks"] == proposed[0]["frameworks"]

    trimmed = resolve_scope_decision(
        "exclude ubuntu_cis_24_l2", proposed
    )
    assert trimmed is not None
    assert all("ubuntu_cis_24_l2" not in r["frameworks"] for r in trimmed)
    assert "postgres_cis" in trimmed[0]["frameworks"]

    emptied = apply_scope_exclusions(
        proposed,
        {"it_audit", "postgres_cis", "ubuntu_cis_24_l2"},
        set(),
    )
    assert emptied == []

    assert resolve_scope_decision("maybe later", proposed) is None
    assert "Proposed host" in format_proposed_jobs_markdown(proposed)

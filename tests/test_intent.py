"""Tests for ad-hoc vs audit intent classification and REQ id parsing."""

from auditor.intent import classify_intent, extract_req_ids


def test_extract_req_ids_normalizes():
    assert extract_req_ids("run REQ-2 and req 10") == ["REQ-002", "REQ-010"]


def test_adhoc_run_command():
    assert classify_intent("Run this command: `grep PermitRootLogin /etc/ssh/sshd_config`") == "adhoc"


def test_adhoc_execute_sql():
    assert classify_intent("Execute SQL: SELECT name, setting FROM pg_settings LIMIT 5") == "adhoc"


def test_adhoc_run_req_playbook():
    # Deterministic playbook path (docs), even when a REQ id is present.
    assert classify_intent("Run playbook commands for REQ-002 on Ubuntu") == "adhoc"


def test_evaluate_req_is_revise():
    assert classify_intent("Evaluate REQ-1. Try read /etc/ssh/sshd_config") == "revise_req"
    assert classify_intent("Gather evidence for REQ-001") == "revise_req"


def test_refill_observation_intent():
    assert (
        classify_intent("Prepare new observation and recommendation for REQ-001")
        == "refill_finding"
    )


def test_refill_beats_update_report():
    assert (
        classify_intent(
            "Prepare new observation and recommendation then update the report"
        )
        == "refill_finding"
    )


def test_broad_verbs_alone_do_not_force_adhoc():
    assert classify_intent("Please try to explain the checklist") == "audit"


def test_adhoc_russian():
    assert classify_intent("Выполни команду `systemctl status ssh`") == "adhoc"


def test_audit_full_cis_still_default():
    assert classify_intent("Start Ubuntu CIS audit on this host") == "audit"


def test_audit_when_audit_word_dominates():
    assert classify_intent("Run a full PostgreSQL CIS audit") == "audit"


def test_empty_defaults_to_audit():
    assert classify_intent("") == "audit"

"""Automated core-flow regression phases for Auditor."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from auditor.api.openai_compat import ChatCompletionRequest, _run_or_resume_once
from auditor.checklist import Requirement
from auditor.config import Settings
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph
from auditor.hitl import build_hitl_prompt, parse_hitl_decision
from auditor.intake import (
    format_host_access_list_markdown,
    format_proposed_jobs_markdown,
    parse_audit_plan_markdown,
    parse_client_name,
    resolve_scope_decision,
    resolve_yes_no,
)
from auditor.secrets_file import InventorySshTarget, list_client_access_endpoints
from auditor.state import Finding


def _settings(tmp_path: Path) -> Settings:
    """Create deterministic settings for tests."""
    return Settings(
        _env_file=None,
        agents_dir=Path("agents"),
        evidence_dir=tmp_path,
        archive_enabled=False,
        intake_enabled=True,
    )


def _fw(fid: str, title: str | None = None) -> SimpleNamespace:
    """Minimal framework-like object with id/title."""
    return SimpleNamespace(id=fid, title=title or fid)


def _target(host: str) -> InventorySshTarget:
    """Minimal SSH target used by scheduler tests."""
    return InventorySshTarget(host=host, user="auditor")


def _summary_table(rows: list[tuple[str, str, str, str]]) -> str:
    """Build a minimal summary table parseable by parse_report_findings()."""
    lines = [
        "# Audit Report",
        "",
        "| REQ-ID | Title | Severity | Status |",
        "|---|---|---|---|",
    ]
    for req_id, title, sev, status in rows:
        lines.append(f"| {req_id} | {title} | {sev} | {status} |")
    return "\n".join(lines)


def test_phase_01_bootstrap_graph_compile(tmp_path: Path):
    graph = AuditorGraph(settings=_settings(tmp_path))
    assert graph.graph is not None
    assert graph.intake_graph is not None


def test_phase_02_config_defaults_smoke(tmp_path: Path):
    settings = _settings(tmp_path)
    assert settings.pg_port == 5432
    assert settings.pg_user == "postgres"
    assert settings.pg_database == "postgres"


def test_phase_03_intake_client_name_en():
    assert parse_client_name("Client: ACME Corp") == "ACME Corp"


def test_phase_04_intake_client_name_ru():
    assert parse_client_name("Клиент: ТестКомпания") == "ТестКомпания"


def test_phase_05_intake_yes_no_resolution():
    assert resolve_yes_no("", {"answer": "yes"}) == "yes"
    assert resolve_yes_no("", {"answer": "нет"}) == "no"
    assert resolve_yes_no("", {"answer": "unknown"}) == "unknown"


def test_phase_06_access_endpoints_empty_rows():
    text = format_host_access_list_markdown([], language="en")
    assert "No access endpoints found in inventory" in text


def test_phase_07_access_endpoints_generic_rows_kept(tmp_path: Path):
    client = tmp_path / "acme"
    client.mkdir()
    (client / "INVENTORY.md").write_text(
        """
| Access | Host / URL | Port | Username | Password / Token | Extra |
|--------|------------|------|----------|------------------|-------|
| Any vendor thing | 10.10.10.10 | 9443 | | | |
""",
        encoding="utf-8",
    )
    rows = list_client_access_endpoints(tmp_path, "acme")
    assert rows
    assert rows[0]["kind"] == "tcp"


def test_phase_08_scope_plan_formatting():
    md = format_proposed_jobs_markdown(
        [{"ssh_host": "10.0.0.1", "hostname": "gw-1", "frameworks": ["checkpoint_ngfw"]}]
    )
    assert "Proposed host" in md
    assert "checkpoint_ngfw" in md


def test_phase_09_scope_confirm_keeps_plan():
    proposed = [{"host_id": "h1", "ssh_host": "10.0.0.1", "frameworks": ["postgres_cis"]}]
    selected = resolve_scope_decision("", proposed, {"action": "confirm"})
    assert selected == proposed


def test_phase_10_scope_exclude_removes_framework():
    proposed = [{"host_id": "h1", "ssh_host": "10.0.0.1", "frameworks": ["postgres_cis", "ubuntu_cis_24_l2"]}]
    selected = resolve_scope_decision(
        "",
        proposed,
        {"action": "exclude", "exclude_frameworks": ["postgres_cis"]},
    )
    assert selected is not None
    assert selected[0]["frameworks"] == ["ubuntu_cis_24_l2"]


def test_phase_11_scope_include_only_subset():
    proposed = [{"host_id": "h1", "ssh_host": "10.0.0.1", "frameworks": ["postgres_cis", "ubuntu_cis_24_l2"]}]
    selected = resolve_scope_decision(
        "",
        proposed,
        {"action": "include", "include_frameworks": ["postgres_cis"]},
    )
    assert selected is not None
    assert selected[0]["frameworks"] == ["postgres_cis"]


def test_phase_12_scope_invalid_action_reprompts():
    proposed = [{"host_id": "h1", "ssh_host": "10.0.0.1", "frameworks": ["postgres_cis"]}]
    assert resolve_scope_decision("", proposed, {"action": "wat"}) is None


def test_phase_13_plan_markdown_ingest():
    plan = """
| Host | Frameworks |
|------|------------|
| 10.0.0.1 | postgres_cis, ubuntu_cis_24_l2 |
"""
    parsed = parse_audit_plan_markdown(plan)
    assert len(parsed) == 1
    assert parsed[0]["ssh_host"] == "10.0.0.1"
    assert set(parsed[0]["frameworks"]) == {"postgres_cis", "ubuntu_cis_24_l2"}


@pytest.mark.asyncio
async def test_phase_14_discovery_fallback_no_jobs(tmp_path: Path):
    graph = AuditorGraph(settings=_settings(tmp_path))
    result = await graph._run_framework_jobs(
        user_text="audit",
        base_thread="t1",
        run_id="run1",
        intake_state={},
        jobs=[],
        plan_md="",
    )
    assert result["report"] == "No frameworks selected."


@pytest.mark.asyncio
async def test_phase_15_single_framework_run_path(tmp_path: Path):
    graph = AuditorGraph(settings=_settings(tmp_path))
    with patch.object(
        graph,
        "_schedule_framework_jobs",
        new=AsyncMock(return_value={"report": "ok", "awaiting_hitl": False}),
    ) as sched:
        result = await graph._run_framework_jobs(
            user_text="audit",
            base_thread="t2",
            run_id="run2",
            intake_state={},
            jobs=[(_target("10.0.0.1"), None, _fw("postgres_cis"))],
            plan_md="",
        )
    assert result["report"] == "ok"
    sched.assert_awaited_once()


@pytest.mark.asyncio
async def test_phase_16_multi_framework_merge_summary_exists(tmp_path: Path):
    graph = AuditorGraph(settings=_settings(tmp_path))
    store = EvidenceStore(tmp_path, run_id="run-merge")
    graph._evidence_by_run["run-merge"] = store
    completed = [
        ("h1/postgres_cis", "10.0.0.1 — PG", _summary_table([("REQ-001", "A", "High", "fail")])),
        ("h2/ubuntu_cis_24_l2", "10.0.0.2 — Ubuntu", _summary_table([("REQ-002", "B", "Low", "pass")])),
    ]
    merged = await graph._merge_multi_reports(completed, run_id="run-merge", base_thread="t3")
    assert "# Management summary" in str(merged["report"])


@pytest.mark.asyncio
async def test_phase_17_management_stats_presence(tmp_path: Path):
    graph = AuditorGraph(settings=_settings(tmp_path))
    store = EvidenceStore(tmp_path, run_id="run-stats")
    graph._evidence_by_run["run-stats"] = store
    completed = [
        (
            "h1/postgres_cis",
            "10.0.0.1 — PG",
            _summary_table(
                [("REQ-001", "A", "Critical", "fail"), ("REQ-002", "B", "Low", "pass")]
            ),
        )
    ]
    merged = await graph._merge_multi_reports(completed, run_id="run-stats", base_thread="t4")
    assert "Pass/Fail statistics:" in str(merged["report"])


@pytest.mark.asyncio
async def test_phase_18_top_findings_cap_10(tmp_path: Path):
    graph = AuditorGraph(settings=_settings(tmp_path))
    store = EvidenceStore(tmp_path, run_id="run-cap")
    graph._evidence_by_run["run-cap"] = store
    rows = [
        (f"REQ-{i:03d}", f"R{i}", "Critical", "fail")
        for i in range(1, 13)
    ]
    completed = [("h1/fw", "host — fw", _summary_table(rows))]
    merged = await graph._merge_multi_reports(completed, run_id="run-cap", base_thread="t5")
    report = str(merged["report"])
    findings = [
        line
        for line in report.splitlines()
        if line.startswith("- [") and "`REQ-" in line
    ]
    assert len(findings) == 10


def test_phase_19_hitl_pause_formatting_hints():
    req = Requirement(
        id="REQ-001",
        title="Check SSH",
        how_to_verify="run command",
        pass_criteria="secure",
    )
    prompt = build_hitl_prompt(
        framework_id="checkpoint_ngfw",
        requirement=req,
        finding=Finding(requirement_id="REQ-001", status="error", evidence="SSH error"),
    )
    assert "Reply with one of" in prompt
    assert "skip" in prompt.lower()
    assert "retry" in prompt.lower()


def test_phase_20_hitl_resume_skip_parse():
    decision = parse_hitl_decision("skip")
    assert decision.action == "skip"


def test_phase_21_hitl_resume_retry_parse():
    decision = parse_hitl_decision("retry")
    assert decision.action == "retry"


@pytest.mark.asyncio
async def test_phase_22_api_intake_pause_resume_flow(monkeypatch):
    auditor = MagicMock()
    auditor.aresume = AsyncMock(return_value={"report": "resumed", "messages": []})
    auditor.arun = AsyncMock()
    auditor.acontinue = AsyncMock()

    settings = MagicMock()
    settings.agents_dir = "agents"
    settings.adhoc_commands_enabled = True
    monkeypatch.setattr("auditor.api.openai_compat.get_settings", lambda: settings)

    body = ChatCompletionRequest(
        messages=[
            {"role": "assistant", "content": "<!-- AUDIT_INTAKE:audit-abc:intake -->"},
            {"role": "user", "content": "testcompany"},
        ]
    )
    result = await _run_or_resume_once(auditor, body)
    assert result["report"] == "resumed"
    auditor.aresume.assert_awaited_once_with("audit-abc:intake", "testcompany")


@pytest.mark.asyncio
async def test_phase_23_continue_interrupted_session(monkeypatch):
    auditor = MagicMock()
    auditor.acontinue = AsyncMock(return_value={"report": "continued", "messages": []})
    settings = MagicMock()
    settings.agents_dir = "agents"
    settings.adhoc_commands_enabled = True
    monkeypatch.setattr("auditor.api.openai_compat.get_settings", lambda: settings)
    monkeypatch.setattr(
        "auditor.api.openai_compat.parse_continue_session_request",
        lambda _txt: (7, "testcompany"),
    )
    monkeypatch.setattr(
        "auditor.api.openai_compat.resolve_continue_target",
        AsyncMock(return_value=("audit-tid", "run-id", {})),
    )

    body = ChatCompletionRequest(messages=[{"role": "user", "content": "continue session 7 for testcompany"}])
    result = await _run_or_resume_once(auditor, body)
    assert result["report"] == "continued"
    auditor.acontinue.assert_awaited_once_with("audit-tid", run_id="run-id")


@pytest.mark.asyncio
async def test_phase_24_finalize_report_persistence(tmp_path: Path):
    graph = AuditorGraph(settings=_settings(tmp_path))
    store = EvidenceStore(tmp_path, run_id="run-persist")
    graph._evidence_by_run["run-persist"] = store
    completed = [("h1/fw1", "host — fw1", _summary_table([("REQ-001", "A", "Low", "pass")]))]
    await graph._merge_multi_reports(completed, run_id="run-persist", base_thread="t6")
    assert (store.root / "report.md").is_file()


@pytest.mark.asyncio
async def test_phase_25_run_or_resume_payload_shape(monkeypatch):
    auditor = MagicMock()
    auditor.arun = AsyncMock(
        return_value={"report": "ok", "messages": [AIMessage(content="ok")], "thread_id": "user-john"}
    )
    settings = MagicMock()
    settings.agents_dir = "agents"
    settings.adhoc_commands_enabled = False
    monkeypatch.setattr("auditor.api.openai_compat.get_settings", lambda: settings)

    body = ChatCompletionRequest(messages=[{"role": "user", "content": "run audit"}], user="john")
    result = await _run_or_resume_once(auditor, body)
    assert set(["report", "messages", "thread_id"]).issubset(result.keys())
    assert result["thread_id"] == "user-john"

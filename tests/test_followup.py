"""Tests for post-audit REQ revise + report update follow-up."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.messages import AIMessage

from auditor.evidence_store import EvidenceStore
from auditor.followup import run_revise_req, run_update_report
from auditor.intent import classify_intent
from auditor.run_resolve import extract_run_id, latest_run_id
from auditor.state import Finding


def test_intent_revise_and_update():
    assert classify_intent("Revise REQ-002 on Ubuntu") == "revise_req"
    assert classify_intent("Run another check for REQ-002: `sshd -T`") == "revise_req"
    assert classify_intent("Проверь REQ-001 ещё раз") == "revise_req"
    assert classify_intent("Update the report from new evidence") == "update_report"
    assert classify_intent("Обнови отчёт") == "update_report"
    # Full audit still wins when clearly requested
    assert classify_intent("Start Ubuntu CIS audit") == "audit"


def test_intent_req_playbook_is_revise():
    assert (
        classify_intent("Run playbook commands for REQ-002 on Ubuntu") == "revise_req"
    )


def test_seed_counters_append_not_overwrite(tmp_path: Path):
    store = EvidenceStore(tmp_path, run_id="20260101T000000Z_deadbeef")
    store.write_tool_result("ubuntu_cis", "REQ-002", "ssh_run", {"command": "a"}, "one")
    store.write_tool_result("ubuntu_cis", "REQ-002", "ssh_run", {"command": "b"}, "two")
    # Re-open as a new store instance (simulates follow-up process)
    reopened = EvidenceStore.open_existing(tmp_path, "20260101T000000Z_deadbeef")
    path = reopened.write_tool_result(
        "ubuntu_cis", "REQ-002", "ssh_run", {"command": "c"}, "three"
    )
    assert path.name.startswith("003_")
    assert (store.root / "ubuntu_cis" / "REQ-002" / "001_ssh_run.txt").is_file()
    assert (store.root / "ubuntu_cis" / "REQ-002" / "003_ssh_run.txt").is_file()


def test_extract_and_latest_run_id(tmp_path: Path):
    rid = "20260720T120000Z_abcdef12"
    EvidenceStore(tmp_path, run_id=rid).write_run_meta(frameworks=["ubuntu_cis"])
    assert extract_run_id(f"evidence: `{tmp_path / rid}`") == rid
    assert latest_run_id(tmp_path) == rid


@pytest.mark.asyncio
async def test_revise_req_writes_into_existing_folder(tmp_path: Path):
    from auditor.config import Settings
    from auditor.graph import AuditorGraph

    rid = "20260720T130000Z_feedbeef"
    store = EvidenceStore(tmp_path, run_id=rid)
    store.write_run_meta(frameworks=["ubuntu_cis"])
    (store.root / "ubuntu_cis" / "REQ-002").mkdir(parents=True)
    store.write_tool_result(
        "ubuntu_cis", "REQ-002", "ssh_run", {"command": "old"}, "PermitRootLogin yes"
    )

    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path,
        memory_enabled=False,
        memory_learn=False,
        benchmark_enabled=False,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)

    finding = Finding(
        requirement_id="REQ-002",
        title="SSH root login disabled",
        status="pass",
        severity="Critical",
        evidence="PermitRootLogin no",
        remediation="",
    )

    async def fake_fill(req_id, requirement, user_request, framework_id, store=None):
        assert store is not None
        assert store.run_id == rid
        # Append a new tool log like the real path would
        store.write_tool_result(
            framework_id,
            req_id,
            "ssh_run",
            {"command": "grep PermitRootLogin"},
            "PermitRootLogin no",
        )
        store.write_finding(framework_id, req_id, finding.model_dump())
        return finding

    graph._fill_requirement_cells = fake_fill  # type: ignore[method-assign]

    result = await run_revise_req(
        graph,
        "Revise REQ-002 on Ubuntu",
        messages=[AIMessage(content=f"evidence: `{store.root}`")],
    )
    assert result["mode"] == "revise_req"
    assert result["evidence_run_id"] == rid
    assert (store.root / "ubuntu_cis" / "REQ-002" / "002_ssh_run.txt").is_file()
    assert (store.root / "ubuntu_cis" / "REQ-002" / "finding.json").is_file()


@pytest.mark.asyncio
async def test_update_report_from_disk_findings(tmp_path: Path):
    from auditor.config import Settings
    from auditor.graph import AuditorGraph

    rid = "20260720T140000Z_cafebabe"
    store = EvidenceStore(tmp_path, run_id=rid)
    store.write_run_meta(frameworks=["ubuntu_cis"])
    finding = {
        "requirement_id": "REQ-002",
        "title": "SSH root login disabled",
        "status": "pass",
        "severity": "Critical",
        "category": "Remote Access",
        "evidence": "PermitRootLogin no",
        "remediation": "",
        "notes": "",
        "pass_criteria": "PermitRootLogin no",
    }
    store.write_finding("ubuntu_cis", "REQ-002", finding)

    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path,
        memory_enabled=False,
        archive_enabled=False,
        compliance_charts_in_report=False,
        benchmark_enabled=False,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)
    graph.fill_model = MagicMock()
    graph.fill_model.ainvoke = AsyncMock(
        return_value=AIMessage(content="Root login is disabled.")
    )

    result = await run_update_report(
        graph,
        "Update the report",
        messages=[AIMessage(content=f"Evidence directory: `{store.root}`")],
    )
    assert result["mode"] == "update_report"
    assert (store.root / "ubuntu_cis" / "report.md").is_file()
    report = (store.root / "report.md").read_text(encoding="utf-8")
    assert "REQ-002" in report
    assert "pass" in report

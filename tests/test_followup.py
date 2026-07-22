"""Tests for post-audit REQ revise + report update follow-up."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.messages import AIMessage

from auditor.evidence_store import EvidenceStore
from auditor.followup import run_refill_finding, run_revise_req, run_update_report
from auditor.intent import classify_intent
from auditor.run_resolve import extract_run_id, latest_run_id
from auditor.state import Finding


def test_intent_revise_and_update():
    assert classify_intent("Revise REQ-002 on Ubuntu") == "revise_req"
    assert classify_intent("Evaluate REQ-1. Try read file") == "revise_req"
    assert classify_intent("List processes for REQ-002") == "revise_req"
    assert classify_intent("Run another check for REQ-002: `sshd -T`") == "revise_req"
    assert classify_intent("Проверь REQ-001 ещё раз") == "revise_req"
    assert (
        classify_intent("Prepare new observation and recommendation for REQ-001")
        == "refill_finding"
    )
    assert classify_intent("Обнови наблюдение для REQ-002") == "refill_finding"
    assert classify_intent("Update the report from new evidence") == "update_report"
    assert classify_intent("Обнови отчёт") == "update_report"
    # Full audit still wins when clearly requested
    assert classify_intent("Start Ubuntu CIS audit") == "audit"


def test_intent_req_playbook_is_adhoc():
    assert classify_intent("Run playbook commands for REQ-002 on Ubuntu") == "adhoc"


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


def test_extract_and_latest_client_named_run(tmp_path: Path):
    rid = "TestCompany"
    EvidenceStore(tmp_path, run_id=rid).write_run_meta(frameworks=["postgres_cis"])
    assert extract_run_id("see `artifacts/TestCompany` for evidence") == "TestCompany"
    assert extract_run_id("/v1/downloads/TestCompany_audit.zip") == "TestCompany"
    assert latest_run_id(tmp_path) == rid
    # Bare ``for <Client>`` when artifacts/<Client> exists
    (tmp_path / "AlphaCo").mkdir()
    (tmp_path / "AlphaCo" / "meta.json").write_text("{}", encoding="utf-8")
    assert extract_run_id("Gather evidence for REQ-001 for AlphaCo", evidence_dir=tmp_path) == "AlphaCo"
    assert extract_run_id("Gather evidence for REQ-001 for AlphaCo") is None


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

    async def fake_fill(
        req_id, requirement, user_request, framework_id, store=None, **_kwargs
    ):
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
    assert result["mode"] == "revise_full"
    assert result["evidence_run_id"] == rid
    assert (store.root / "ubuntu_cis" / "REQ-002" / "002_ssh_run.txt").is_file()
    assert (store.root / "ubuntu_cis" / "REQ-002" / "finding.json").is_file()


@pytest.mark.asyncio
async def test_evaluate_req_gathers_evidence_only(tmp_path: Path):
    from auditor.config import Settings
    from auditor.graph import AuditorGraph

    rid = "20260720T131500Z_feedbeef"
    store = EvidenceStore(tmp_path, run_id=rid)
    store.write_run_meta(frameworks=["ubuntu_cis"])
    (store.root / "ubuntu_cis" / "REQ-001").mkdir(parents=True)

    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path,
        memory_enabled=False,
        memory_learn=False,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)

    async def fake_gather(req_id, requirement, user_request, framework_id, store=None):
        assert store is not None
        store.write_tool_result(
            framework_id,
            req_id,
            "ssh_run",
            {"command": "ps aux"},
            "root 1 ...",
        )
        return "[ssh_run] root 1 ..."

    graph._gather_evidence = fake_gather  # type: ignore[method-assign]

    result = await run_revise_req(
        graph,
        "Evaluate REQ-1. Try list processes",
        messages=[AIMessage(content=f"evidence: `{store.root}`")],
    )
    assert result["mode"] == "gather_evidence"
    assert (store.root / "ubuntu_cis" / "REQ-001" / "001_ssh_run.txt").is_file()
    assert not (store.root / "ubuntu_cis" / "REQ-001" / "finding.json").is_file()


@pytest.mark.asyncio
async def test_refill_without_req_requires_revised_or_named(tmp_path: Path):
    from auditor.config import Settings
    from auditor.graph import AuditorGraph
    from langchain_core.messages import AIMessage as AIM

    rid = "20260720T131800Z_feedbeef"
    store = EvidenceStore(tmp_path, run_id=rid)
    store.write_run_meta(frameworks=["ubuntu_cis"])
    (store.root / "ubuntu_cis" / "REQ-001").mkdir(parents=True)
    (store.root / "ubuntu_cis" / "REQ-002").mkdir(parents=True)

    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path,
        memory_enabled=False,
        memory_learn=False,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)
    result = await run_refill_finding(
        graph,
        "Prepare new observation and recommendation",
        messages=[AIM(content=f"evidence: `{store.root}`")],
    )
    assert result.get("error")
    assert "REQ-001" in str(result["error"]) or "requirement" in str(result["error"]).lower()


@pytest.mark.asyncio
async def test_refill_finding_from_stored_evidence(tmp_path: Path):
    from auditor.config import Settings
    from auditor.graph import AuditorGraph
    from langchain_core.messages import AIMessage as AIM

    rid = "20260720T132000Z_feedbeef"
    store = EvidenceStore(tmp_path, run_id=rid)
    store.write_run_meta(frameworks=["ubuntu_cis"], report_language="en")
    store.write_tool_result(
        "ubuntu_cis",
        "REQ-001",
        "ssh_run",
        {"command": "ps"},
        "root 1 init",
    )

    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path,
        memory_enabled=False,
        memory_learn=False,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)

    class _Resp:
        content = (
            '{"status":"fail","observation":"init running as pid 1",'
            '"recommendation":"review processes"}'
        )

    graph.fill_model = MagicMock()
    graph.fill_model.ainvoke = AsyncMock(return_value=_Resp())

    result = await run_refill_finding(
        graph,
        "Prepare new observation and recommendation for REQ-001",
        messages=[AIM(content=f"evidence: `{store.root}`")],
    )
    assert result["mode"] == "refill_finding"
    finding = store.load_finding("ubuntu_cis", "REQ-001")
    assert finding is not None
    assert finding["status"] == "fail"
    assert "pid 1" in finding["evidence"]


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


def test_resolve_multi_host_req_with_host_hint(tmp_path: Path):
    from auditor.run_resolve import resolve_framework_for_req, resolve_target

    rid = "TestCompany"
    store = EvidenceStore(tmp_path, run_id=rid)
    store.write_run_meta(frameworks=["ubuntu_cis"])
    for host in ("10.200.29.78", "10.200.29.79"):
        key = f"{host}/ubuntu_cis"
        (store.root / key / "REQ-010").mkdir(parents=True)
        store.write_finding(
            key,
            "REQ-010",
            {
                "requirement_id": "REQ-010",
                "title": "demo",
                "status": "fail",
                "severity": "High",
                "evidence": "x",
                "remediation": "",
            },
        )

    chosen = resolve_framework_for_req(
        user_text="Evaluate REQ-010 on ubuntu_cis for host 10.200.29.78",
        store=store,
        req_id="REQ-010",
        agents_dir=Path("agents"),
    )
    assert chosen == "10.200.29.78/ubuntu_cis"

    target = resolve_target(
        user_text="Evaluate REQ-010 on ubuntu_cis for host 10.200.29.78",
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        require_req=True,
    )
    assert target.framework_id == "10.200.29.78/ubuntu_cis"
    assert target.host_id == "10.200.29.78"

    with pytest.raises(ValueError, match="multiple frameworks/hosts"):
        resolve_framework_for_req(
            user_text="Evaluate REQ-010 on ubuntu_cis",
            store=store,
            req_id="REQ-010",
            agents_dir=Path("agents"),
        )


@pytest.mark.asyncio
async def test_revise_req_multi_host_path(tmp_path: Path):
    from auditor.config import Settings
    from auditor.graph import AuditorGraph

    rid = "TestCompany"
    store = EvidenceStore(tmp_path, run_id=rid)
    store.write_run_meta(frameworks=["ubuntu_cis"])
    fw_key = "10.200.29.78/ubuntu_cis"
    (store.root / fw_key / "REQ-010").mkdir(parents=True)

    settings = Settings(
        agents_dir=Path("agents"),
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        evidence_dir=tmp_path,
        inventory_dir=tmp_path / "inventory",
        memory_enabled=False,
        memory_learn=False,
        litellm_base_url="http://localhost:9",
    )
    graph = AuditorGraph(settings=settings)

    async def fake_gather(req_id, requirement, user_request, framework_id, store=None):
        assert framework_id == fw_key
        assert store is not None
        store.write_tool_result(
            framework_id,
            req_id,
            "ssh_run",
            {"command": "sshd -T"},
            "permitrootlogin no",
        )
        return "[ssh_run] permitrootlogin no"

    graph._gather_evidence = fake_gather  # type: ignore[method-assign]

    result = await run_revise_req(
        graph,
        "Evaluate REQ-010 on ubuntu_cis for host 10.200.29.78. Check PermitRootLogin",
        messages=[AIMessage(content=f"evidence: `{store.root}`")],
    )
    assert result["mode"] == "gather_evidence"
    assert result["framework_id"] == fw_key
    assert (store.root / fw_key / "REQ-010" / "001_ssh_run.txt").is_file()

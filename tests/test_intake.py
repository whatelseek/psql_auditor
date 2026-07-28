"""Unit tests for pre-audit intake parsers and audit-type routing."""

from pathlib import Path

import pytest

from auditor.frameworks import select_frameworks_for_host
from auditor.hitl import resolve_pause_resume
from auditor.host_facts import HostFacts, parse_host_facts_json
from auditor.intake import (
    apply_scope_exclusions,
    client_slug,
    domains_for_audit_type,
    enrich_facts_from_access_rows,
    extract_management_summary,
    format_discovered_software_markdown,
    format_host_access_list_markdown,
    format_proposed_jobs_markdown,
    frameworks_for_audit_type,
    intake_clarification_from_payload,
    load_client_audit_plan,
    parse_audit_plan_markdown,
    parse_client_name,
    resolve_audit_type,
    resolve_client_name,
    resolve_scope_decision,
    resolve_yes_no,
)


def test_resolve_yes_no_llm_payload():
    # Steps 2–3: intake interpret model decides; we only normalize its answer.
    assert resolve_yes_no("yes", {"answer": "no"}) == "no"
    assert resolve_yes_no("no", {"answer": "yes"}) == "yes"
    assert resolve_yes_no("We track assets in Excel", {"answer": "no"}) == "no"
    assert resolve_yes_no("nayn", {"answer": "no"}) == "no"
    assert resolve_yes_no("yep!", {"answer": "yes"}) == "yes"
    assert resolve_yes_no("Follow white rabbit", {"answer": "unknown"}) == "unknown"
    assert resolve_yes_no("maybe", {"answer": "unknown"}) == "unknown"
    assert resolve_yes_no("no", None) == "unknown"
    assert resolve_yes_no("yes", {}) == "unknown"
    assert resolve_yes_no("ага", {"answer": "unknown"}) == "unknown"
    # Model echoed slang into answer — normalize label only
    assert resolve_yes_no("ага", {"answer": "ага"}) == "yes"
    assert resolve_yes_no("угу", {"answer": "yes"}) == "yes"
    assert resolve_yes_no("неа", {"answer": "no"}) == "no"
    assert resolve_yes_no("ну ты можешь попасть, я нет", {"answer": "yes"}) == "yes"
    assert resolve_yes_no("ну ты можешь попасть, я нет", None) == "unknown"


def test_intake_clarification_from_payload():
    assert intake_clarification_from_payload(None) == ""
    assert intake_clarification_from_payload({"answer": "unknown"}) == ""
    assert (
        intake_clarification_from_payload(
            {
                "answer": "unknown",
                "clarification": "Это вопрос про доступ по SSH.",
            }
        )
        == "Это вопрос про доступ по SSH."
    )
    assert (
        intake_clarification_from_payload({"help": "Explain what access means."})
        == "Explain what access means."
    )


def test_resolve_client_and_audit_type_llm():
    # Step 1 is deterministic — LLM payload ignored
    assert resolve_client_name("whatever", {"client_name": "Acme Corp"}) == "whatever"
    assert resolve_client_name("Client: Acme", None) == "Acme"
    assert (
        resolve_audit_type("please do cyber stuff", {"audit_type": "cybersecurity"})
        == "cybersecurity"
    )
    # Step 4: no regex fallback when LLM omits / nulls audit_type
    assert resolve_audit_type("both", {"audit_type": None}) is None
    assert resolve_audit_type("both", None) is None
    assert resolve_audit_type("garbage", {"audit_type": None}) is None
    assert resolve_audit_type("both", {"audit_type": "both"}) == "both"


def test_resolve_scope_llm_only():
    proposed = [
        {
            "host_id": "10_0_0_1",
            "hostname": "pg-db",
            "ssh_host": "10.0.0.1",
            "frameworks": ["it_audit", "postgres_cis", "ubuntu_cis_24_l2"],
        }
    ]
    selected = resolve_scope_decision(
        "looks good, ship it",
        proposed,
        {"action": "confirm"},
    )
    assert selected is not None
    assert len(selected) == 1
    trimmed = resolve_scope_decision(
        "drop ubuntu please",
        proposed,
        {
            "action": "exclude",
            "exclude_frameworks": ["ubuntu_cis_24_l2"],
            "exclude_pairs": [],
        },
    )
    assert trimmed is not None
    assert "ubuntu_cis_24_l2" not in trimmed[0]["frameworks"]
    assert "postgres_cis" in trimmed[0]["frameworks"]
    only = resolve_scope_decision(
        "only postgres",
        proposed,
        {
            "action": "include",
            "include_frameworks": ["postgres_cis"],
            "include_pairs": [],
        },
    )
    assert only is not None
    assert only[0]["frameworks"] == ["postgres_cis"]
    only_pair = resolve_scope_decision(
        "only ubuntu on this host",
        proposed,
        {
            "action": "include",
            "include_frameworks": [],
            "include_pairs": ["10.0.0.1/ubuntu_cis_24_l2"],
        },
    )
    assert only_pair is not None
    assert only_pair[0]["frameworks"] == ["ubuntu_cis_24_l2"]
    # Empty include lists → re-prompt
    assert (
        resolve_scope_decision(
            "only something",
            proposed,
            {"action": "include", "include_frameworks": [], "include_pairs": []},
        )
        is None
    )
    # No regex fallback — bare confirm / missing payload → re-prompt
    assert resolve_scope_decision("confirm", proposed, {"action": "unknown"}) is None
    assert resolve_scope_decision("confirm", proposed, None) is None
    assert resolve_scope_decision("maybe later", proposed, None) is None


def test_parse_client_and_slug():
    assert parse_client_name("Client: Acme Corp") == "Acme Corp"
    assert client_slug("Acme Corp!") == "acme_corp"


def test_parse_audit_plan_markdown_table_and_bullets():
    table = """
| Host / IP | Frameworks / checks |
|-----------|---------------------|
| 10.0.0.10 | postgres_cis, ubuntu_cis_24_l2 |
| 10.0.0.20 | it_audit |
"""
    jobs = parse_audit_plan_markdown(table)
    assert len(jobs) == 2
    assert jobs[0]["ssh_host"] == "10.0.0.10"
    assert jobs[0]["frameworks"] == ["postgres_cis", "ubuntu_cis_24_l2"]
    assert jobs[1]["frameworks"] == ["it_audit"]

    bullets = """
- 10.0.0.10: postgres_cis, ubuntu_cis_24_l2
- 10.0.0.20: it_audit
"""
    assert [j["ssh_host"] for j in parse_audit_plan_markdown(bullets)] == [
        "10.0.0.10",
        "10.0.0.20",
    ]
    filtered = parse_audit_plan_markdown(table, known_framework_ids={"postgres_cis", "it_audit"})
    assert filtered[0]["frameworks"] == ["postgres_cis"]
    assert parse_audit_plan_markdown("no plan here") == []


def test_load_client_audit_plan(tmp_path: Path):
    client = tmp_path / "Acme"
    client.mkdir()
    (client / "PLAN.md").write_text(
        "| Host | Frameworks |\n|------|------------|\n| 10.1.1.1 | it_audit |\n",
        encoding="utf-8",
    )
    jobs, path = load_client_audit_plan(tmp_path, "Acme")
    assert path is not None and path.name == "PLAN.md"
    assert jobs[0]["ssh_host"] == "10.1.1.1"
    assert jobs[0]["frameworks"] == ["it_audit"]


def test_load_client_audit_plan_falls_back_to_inventory_root(tmp_path: Path):
    (tmp_path / "Acme").mkdir()
    (tmp_path / "PLAN.md").write_text(
        "| Host | Frameworks |\n|------|------------|\n| 10.2.2.2 | postgres_cis |\n",
        encoding="utf-8",
    )
    jobs, path = load_client_audit_plan(tmp_path, "Acme")
    assert path == tmp_path / "PLAN.md"
    assert jobs[0]["ssh_host"] == "10.2.2.2"
    assert jobs[0]["frameworks"] == ["postgres_cis"]


def test_looks_like_plan_file_notice():
    from auditor.intake import looks_like_plan_file_notice

    assert looks_like_plan_file_notice("положил")
    assert looks_like_plan_file_notice("положил PLAN.md")
    assert looks_like_plan_file_notice("I put PLAN.md")
    assert not looks_like_plan_file_notice("подтвердить")
    assert not looks_like_plan_file_notice("exclude ubuntu")


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
    assert resolve_pause_resume(msgs) == ("intake", "audit-abc:intake")


def test_frameworks_for_audit_type_it(tmp_path: Path):
    # Use real agents/ if present
    agents = Path("agents")
    if not (agents / "it_audit.md").is_file():
        return
    assert frameworks_for_audit_type("it", user_request="start it audit", agents_dir=agents) == [
        "it_audit"
    ]
    both = frameworks_for_audit_type("both", user_request="postgres cis", agents_dir=agents)
    assert both[0] == "it_audit"
    assert "it_audit" not in both[1:]


def test_scope_exclusions_via_llm_resolve():
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
    selected = resolve_scope_decision("confirm", proposed, {"action": "confirm"})
    assert selected is not None
    assert len(selected) == 2
    assert selected[0]["frameworks"] == proposed[0]["frameworks"]

    trimmed = resolve_scope_decision(
        "exclude ubuntu_cis_24_l2",
        proposed,
        {
            "action": "exclude",
            "exclude_frameworks": ["ubuntu_cis_24_l2"],
            "exclude_pairs": [],
        },
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

    only = resolve_scope_decision(
        "only it_audit and postgres",
        proposed,
        {
            "action": "include",
            "include_frameworks": ["it_audit", "postgres_cis"],
            "include_pairs": [],
        },
    )
    assert only is not None
    assert only[0]["frameworks"] == ["it_audit", "postgres_cis"]
    assert only[1]["frameworks"] == ["it_audit"]

    assert resolve_scope_decision("maybe later", proposed) is None
    assert "Proposed host" in format_proposed_jobs_markdown(proposed)


def test_parse_host_facts_json_llm_payload():
    facts = parse_host_facts_json(
        {
            "hostname": "db1",
            "ips": ["10.0.0.1"],
            "os_id": "ubuntu",
            "os_pretty_name": "Ubuntu 24.04.2 LTS",
            "binaries": ["psql", "postgres"],
            "packages": ["postgresql-16", "mysql-server"],
            "key_files": ["/etc/postgresql"],
            "listening_ports": [5432],
        },
        ssh_host="10.0.0.1",
    )
    assert facts.hostname == "db1"
    assert "psql" in facts.binaries
    assert "mysql-server" in facts.packages
    assert facts.os_id == "ubuntu"
    assert 5432 in facts.listening_ports


def test_framework_matches_host_via_package_name():
    from auditor.frameworks import Framework, FrameworkDetect, framework_matches_host

    fw = Framework(
        id="mysql_cis",
        title="MySQL",
        path=__file__,  # unused
        description="test",
        domain="cybersecurity",
        detect=FrameworkDetect(binaries=("mysql", "mysqld")),
    )
    facts = HostFacts(packages=["mysql-server", "bash"])
    assert framework_matches_host(fw, facts)


def test_format_discovered_software_markdown():
    md = format_discovered_software_markdown(
        [
            {
                "ssh_host": "10.0.0.1",
                "hostname": "db-01",
                "os_pretty_name": "Ubuntu 24.04",
                "binaries": ["psql", "postgres"],
                "packages": ["postgresql-16"],
                "key_files": ["/etc/postgresql"],
            }
        ]
    )
    assert "framework selection" in md.lower() or "фреймворк" in md.lower()
    assert "postgresql-16" in md
    assert "/etc/postgresql" in md
    assert "psql" in md


def test_enrich_facts_from_access_rows_adds_postgres():
    # Checklist fill missed postgres; inventory PG endpoint is up.
    facts = HostFacts(
        hostname="pg-server",
        os_id="ubuntu",
        binaries=["hostnamectl", "cat"],
        listening_ports=[22],
    )
    enrich_facts_from_access_rows(
        facts,
        "10.200.29.79",
        [
            {
                "service": "PostgreSQL",
                "host": "10.200.29.79",
                "port": "5432",
                "kind": "pg",
                "status": "accessible",
            }
        ],
    )
    assert 5432 in facts.listening_ports
    assert "psql" in facts.binaries
    ids = [
        fw.id
        for fw in select_frameworks_for_host(
            facts, domains=["it", "cybersecurity"], agents_dir="agents"
        )
    ]
    assert "postgres_cis" in ids


def test_format_host_access_list_markdown():
    md = format_host_access_list_markdown(
        [
            {
                "service": "db-01",
                "host": "10.0.0.1",
                "port": "22",
                "status": "accessible",
            },
            {
                "service": "PostgreSQL",
                "host": "10.0.0.1",
                "port": "5432",
                "kind": "pg",
                "status": "not accessible",
            },
        ],
        proposed_jobs=[
            {
                "ssh_host": "10.0.0.1",
                "frameworks": ["it_audit", "ubuntu_cis_24_l2", "postgres_cis"],
            }
        ],
    )
    assert "Hostname / Service" in md
    assert "Applicable frameworks" in md
    assert "db-01" in md
    assert "5432" in md
    assert "not accessible" in md
    assert "ubuntu_cis_24_l2" in md
    assert "postgres_cis" in md
    assert "Frameworks" not in md


def test_extract_management_summary():
    report = (
        "Client: **Acme** | Framework: `ubuntu_cis`\n\n"
        "## Management summary\n\n"
        "Key risks fixed on SSH.\n\n"
        "---\n\n"
        "| REQ-001 | fail |\n"
        "### REQ-001\n\n"
        "long evidence\n"
    )
    summary = extract_management_summary(report)
    assert "Key risks" in summary or "Management summary" in summary
    assert "REQ-001" not in summary or summary.index("Management") < summary.find("REQ")


@pytest.mark.asyncio
async def test_aresume_preidentity_intake_allows_known_pause(tmp_path: Path):
    """First intake interrupt uses audit-{hex}:intake before client/run IDs exist."""
    import types

    from langgraph.types import interrupt

    from auditor.config import Settings
    from auditor.graph import AuditorGraph

    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        inventory_dir=tmp_path / "inventory",
        intake_enabled=True,
        hitl_enabled=False,
        checkpoint_path=tmp_path / "cp.sqlite",
    )
    (tmp_path / "inventory").mkdir()
    graph = AuditorGraph(settings=settings)
    await graph.ensure_async_checkpointer()

    async def stub_gate(self, state):
        interrupt({"type": "intake", "prompt": "Q1?", "step": "a"})
        interrupt({"type": "intake", "prompt": "Q2?", "step": "b"})
        return {"intake_complete": False, "intake": {}}

    graph.intake_gate = types.MethodType(stub_gate, graph)
    graph.intake_graph = graph._build_intake()

    paused = await graph.arun("start audit")
    assert paused.get("awaiting_hitl") is True
    tid = str(paused.get("thread_id") or "")
    assert ":intake" in tid
    assert tid.startswith("audit-")

    # No client_id / audit_run_id — previously raised unbound checkpoint access.
    resumed = await graph.aresume(tid, "answer-one")
    assert resumed.get("awaiting_hitl") is True
    assert "Q2" in (resumed.get("report") or "")

    # After multi-session drop, interrupted checkpoint alone still authorizes resume.
    graph._forget_multi_session(tid)
    resumed2 = await graph.aresume(tid, "answer-two")
    # Stub gate finishes; no further interrupt.
    assert resumed2.get("awaiting_hitl") is False


@pytest.mark.asyncio
async def test_aresume_preidentity_intake_refuses_unbound(tmp_path: Path):
    from auditor.config import Settings
    from auditor.graph import AuditorGraph
    from auditor.run_scope import RunScopeIsolationError

    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        inventory_dir=tmp_path / "inventory",
        intake_enabled=True,
        checkpoint_path=tmp_path / "cp.sqlite",
    )
    (tmp_path / "inventory").mkdir()
    graph = AuditorGraph(settings=settings)
    await graph.ensure_async_checkpointer()
    with pytest.raises(RunScopeIsolationError, match="refusing unbound"):
        await graph.aresume("audit-deadbeef12:intake", "Acme_Corp")


@pytest.mark.unit
def test_load_intake_progress_restores_identity_not_answers(tmp_path: Path):
    """Resume must reuse audit_run_id without restoring questionnaire answers."""
    from auditor.config import Settings
    from auditor.evidence_store import EvidenceStore
    from auditor.graph import AuditorGraph
    from auditor.workflows.intake import load_intake_progress, persist_intake_progress

    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        inventory_dir=tmp_path / "inventory",
        intake_enabled=True,
    )
    (tmp_path / "inventory").mkdir()
    graph = AuditorGraph(settings=settings)
    store = EvidenceStore(tmp_path, run_id="tmp_intake")
    graph._evidence_by_run[store.run_id] = store
    state = {"evidence_run_id": store.run_id, "thread_id": "audit-abc:intake", "intake": {}}
    persist_intake_progress(
        graph,
        state,
        {
            "client_name": "Acme",
            "client_id": "client_aaaaaaaaaaaaaa",
            "audit_run_id": "arun_bbbbbbbbbbbbbb",
            "client_slug": "acme",
            "has_access": "yes",
            "discovery_complete": True,
            "proposed_jobs": [{"ssh_host": "10.0.0.1"}],
        },
        thread_id="audit-abc:intake",
    )
    loaded = load_intake_progress(graph, state, thread_id="audit-abc:intake")
    assert loaded.get("audit_run_id") == "arun_bbbbbbbbbbbbbb"
    assert loaded.get("client_id") == "client_aaaaaaaaaaaaaa"
    assert loaded.get("client_slug") == "acme"
    assert loaded.get("discovery_complete") is True
    assert loaded.get("proposed_jobs")
    # Answers must not be restored (would skip interrupt replay).
    assert "client_name" not in loaded
    assert "has_access" not in loaded


def test_format_intake_assistant_message_visible_marker():
    from auditor.hitl import resolve_pause_resume
    from auditor.intake import format_intake_assistant_message

    msg = format_intake_assistant_message("## Pre-audit intake (1/3)", "audit-abc:intake")
    assert "[AUDIT_INTAKE:audit-abc:intake]" in msg
    assert "[//]: # (AUDIT_INTAKE:" not in msg
    assert resolve_pause_resume(
        [{"role": "assistant", "content": msg}, {"role": "user", "content": "Acme"}]
    ) == ("intake", "audit-abc:intake")


@pytest.mark.unit
def test_resolve_intake_evidence_store_prefers_rebound_run(tmp_path: Path):
    """Resume must read intake progress from rebound client store, not temp run."""
    from auditor.audit_registry import AuditRegistry
    from auditor.config import Settings
    from auditor.evidence_store import EvidenceStore
    from auditor.graph import AuditorGraph
    from auditor.workflows.intake import (
        load_intake_progress,
        persist_intake_progress,
        resolve_intake_evidence_store,
    )

    settings = Settings(
        _env_file=None,
        evidence_dir=tmp_path,
        agents_dir=Path("agents"),
        inventory_dir=tmp_path / "inventory",
        intake_enabled=True,
    )
    (tmp_path / "inventory").mkdir()
    graph = AuditorGraph(settings=settings)

    temp = EvidenceStore(tmp_path, run_id="20260101T000000Z_temp")
    graph._evidence_by_run[temp.run_id] = temp

    client_store = EvidenceStore(tmp_path, run_id="acme/arun_cccccccccccccccc")
    graph._evidence_by_run[client_store.run_id] = client_store
    persist_intake_progress(
        graph,
        {"evidence_run_id": client_store.run_id, "thread_id": "audit-abc:intake", "intake": {}},
        {
            "client_id": "client_aaaaaaaaaaaaaa",
            "audit_run_id": "arun_cccccccccccccccc",
            "client_slug": "acme",
            "artifacts_run_id": client_store.run_id,
            "discovery_complete": True,
            "proposed_jobs": [
                {"host_id": "h1", "ssh_host": "10.0.0.1", "frameworks": ["ubuntu_cis_24_l2"]}
            ],
        },
        thread_id="audit-abc:intake",
    )
    registry = AuditRegistry(tmp_path / ".audit_registry.sqlite")
    registry.create_run(
        client_id="client_aaaaaaaaaaaaaa",
        scope={"client_slug": "acme"},
        evidence_run_id=client_store.run_id,
        base_thread_id="audit-abc:intake",
        audit_run_id="arun_cccccccccccccccc",
    )

    # Simulate resume: checkpoint still points at temp run.
    state = {"evidence_run_id": temp.run_id, "thread_id": "audit-abc:intake", "intake": {}}
    store = resolve_intake_evidence_store(graph, state, thread_id="audit-abc:intake")
    assert store is not None
    assert store.run_id == client_store.run_id
    loaded = load_intake_progress(graph, state, thread_id="audit-abc:intake")
    assert loaded.get("proposed_jobs")
    assert loaded.get("discovery_complete") is True


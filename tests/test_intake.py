"""Unit tests for pre-audit intake parsers and audit-type routing."""

from pathlib import Path

from auditor.host_facts import HostFacts, parse_host_facts_json
from auditor.frameworks import select_frameworks_for_host
from auditor.hitl import resolve_pause_resume
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
    assert (
        resolve_yes_no("ну ты можешь попасть, я нет", {"answer": "yes"}) == "yes"
    )
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
    assert frameworks_for_audit_type(
        "it", user_request="start it audit", agents_dir=agents
    ) == ["it_audit"]
    both = frameworks_for_audit_type(
        "both", user_request="postgres cis", agents_dir=agents
    )
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
    selected = resolve_scope_decision(
        "confirm", proposed, {"action": "confirm"}
    )
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

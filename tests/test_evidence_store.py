from pathlib import Path

from auditor.evidence_store import EvidenceStore


def test_evidence_store_creates_per_requirement_folders(tmp_path: Path):
    store = EvidenceStore(tmp_path, run_id="run_test")
    store.write_run_meta(user_request="audit postgres")
    store.write_requirement(
        "postgres_cis",
        "REQ-001",
        {"id": "REQ-001", "title": "SSL"},
    )
    path = store.write_tool_result(
        "postgres_cis",
        "REQ-001",
        "mcp_query",
        {"sql": "SHOW ssl"},
        "ssl | on",
    )
    store.write_finding(
        "postgres_cis",
        "REQ-001",
        {
            "requirement_id": "REQ-001",
            "status": "pass",
            "client_id": "client_test00000001",
            "audit_run_id": "arun_test0000000001",
        },
    )

    req_dir = store.root / "postgres_cis" / "REQ-001"
    assert req_dir.is_dir()
    assert (req_dir / "requirement.json").is_file()
    assert (req_dir / "finding.json").is_file()
    assert path.name == "001_mcp_query.txt"
    assert "SHOW ssl" in path.read_text(encoding="utf-8")
    assert "ssl | on" in path.read_text(encoding="utf-8")
    assert (req_dir / "001_mcp_query.json").is_file()
    assert (store.root / "meta.json").is_file()


def test_evidence_store_redacts_password_args(tmp_path: Path):
    import json

    store = EvidenceStore(tmp_path, run_id="run_secret")
    path = store.write_tool_result(
        "postgres_cis",
        "REQ-001",
        "mcp_connect_db",
        {"host": "db", "password": "s3cret", "user": "postgres"},
        "ok",
    )
    text = path.read_text(encoding="utf-8")
    assert "s3cret" not in text
    assert "***REDACTED***" in text
    sidecar = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    assert sidecar["arguments"]["password"] == "***REDACTED***"


def test_deterministic_it_audit_req006_without_cmdb(tmp_path: Path):
    from auditor.checklist import Requirement
    from auditor.config import Settings
    from auditor.evidence_store import EvidenceStore
    from auditor.graph import AuditorGraph

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
    store = EvidenceStore(tmp_path, run_id="TestCompany")
    (store.root / "INVENTORY.md").write_text("# inv\n", encoding="utf-8")
    req = Requirement(
        id="REQ-006",
        title="Inventory consistency",
        category="Inventory",
        severity="High",
        how_to_verify="x",
        pass_criteria="y",
    )
    finding = graph._deterministic_it_audit_finding(
        req_id="REQ-006",
        requirement=req,
        framework_id="it_audit",
        state={"has_cmdb": False, "intake": {"has_cmdb": False}},
        store=store,
    )
    assert finding is not None
    assert finding.status == "pass"
    assert "INVENTORY.md" in finding.evidence


def test_deterministic_it_audit_req007_from_probe():
    from pathlib import Path

    from auditor.checklist import Requirement
    from auditor.config import Settings
    from auditor.graph import AuditorGraph

    graph = AuditorGraph(
        settings=Settings(
            agents_dir=Path("agents"),
            playbooks_dir=Path("agents/playbooks"),
            memory_enabled=False,
            memory_learn=False,
            litellm_base_url="http://localhost:9",
        )
    )
    req = Requirement(
        id="REQ-007",
        title="Service reachability summary",
        category="Access",
        severity="Medium",
        how_to_verify="x",
        pass_criteria="y",
    )
    finding = graph._deterministic_it_audit_finding(
        req_id="REQ-007",
        requirement=req,
        framework_id="it_audit",
        state={
            "intake": {
                "access_probe": {
                    "any_ok": True,
                    "services": [
                        {"name": "ssh", "status": "ok", "detail": "up"},
                        {"name": "postgres_mcp", "status": "ok", "detail": "up"},
                    ],
                }
            }
        },
        store=None,
    )
    assert finding is not None
    assert finding.status == "pass"
    assert "ssh" in finding.evidence


def test_write_report_does_not_overwrite_root(tmp_path: Path):
    store = EvidenceStore(tmp_path, run_id="run_multi")
    store.write_root_report("# combined\n")
    store.write_report("it_audit", "# it only\n")
    assert (store.root / "it_audit" / "report.md").read_text(encoding="utf-8").startswith("# it")
    assert (store.root / "report.md").read_text(encoding="utf-8").startswith("# combined")

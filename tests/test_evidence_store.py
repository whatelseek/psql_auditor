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
        {"requirement_id": "REQ-001", "status": "pass"},
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


def test_evidence_store_sequences_multiple_commands(tmp_path: Path):
    store = EvidenceStore(tmp_path, run_id="run_seq")
    p1 = store.write_tool_result("ubuntu_cis", "REQ-002", "ssh_run", {"command": "id"}, "uid=0")
    p2 = store.write_tool_result(
        "ubuntu_cis",
        "REQ-002",
        "ssh_read_file",
        {"path": "/etc/ssh/sshd_config"},
        "PermitRootLogin no",
    )
    assert p1.name.startswith("001_")
    assert p2.name.startswith("002_")
    assert p1.parent == p2.parent

from pathlib import Path

from auditor.memory.playbook_store import PlaybookMemory


def test_loads_seed_playbooks_from_agents(tmp_path: Path):
    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        learn=False,
    )
    entry = mem.get_entry("ubuntu_cis_24_l2", "REQ-001")
    assert entry is not None
    assert entry["tools"]
    assert entry["tools"][0]["name"] == "ssh_run"

    pg = mem.get_entry("postgres_cis", "REQ-001")
    assert pg is not None
    assert pg["tools"][0]["name"] == "mcp_query"
    assert "password_encryption" in pg["tools"][0]["arguments"]["sql"]


def test_format_prompt_block_includes_preferred_tools(tmp_path: Path):
    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        learn=False,
    )
    block = mem.format_prompt_block("ubuntu_cis_24_l2", "REQ-001")
    assert "playbook memory" in block.lower()
    assert "ssh_run" in block


def test_host_prefixed_framework_uses_same_playbook_ns(tmp_path: Path):
    """Multi-host evidence keys must not break LangGraph namespace rules."""
    from auditor.memory.playbook_store import _memory_framework_id, _ns

    assert _memory_framework_id("10.200.29.78/ubuntu_cis_24_l2") == "ubuntu_cis_24_l2"
    assert _ns("10.200.29.78/ubuntu_cis_24_l2") == ("playbooks", "ubuntu_cis_24_l2")

    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        learn=True,
    )
    block = mem.format_prompt_block("10.200.29.78/ubuntu_cis_24_l2", "REQ-001")
    assert "ssh_run" in block
    mem.remember_tool(
        "10.200.29.78/ubuntu_cis_24_l2",
        "REQ-010",
        "ssh_run",
        {"command": "grep use_pty /etc/sudoers"},
        success=True,
    )
    entry = mem.get_entry("ubuntu_cis_24_l2", "REQ-010")
    assert entry is not None
    assert entry["tools"][0]["name"] == "ssh_run"


def test_remember_tool_persists_learned_overlay(tmp_path: Path):
    memory_dir = tmp_path / "memory"
    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=memory_dir,
        learn=True,
        # Warehouse off → JSON fallback
        settings=None,
    )
    mem.remember_tool(
        "ubuntu_cis_24_l2",
        "REQ-099",
        "ssh_run",
        {"command": "echo learned-ok"},
        success=True,
    )
    learned_path = memory_dir / "learned_playbooks.json"
    assert learned_path.is_file()

    mem2 = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=memory_dir,
        learn=True,
    )
    entry = mem2.get_entry("ubuntu_cis_24_l2", "REQ-099")
    assert entry is not None
    assert entry["source"] == "learned"
    assert entry["tools"][0]["arguments"]["command"] == "echo learned-ok"


def test_remember_persists_via_results_postgres(tmp_path: Path, monkeypatch):
    """When RESULTS warehouse is enabled, learned recipes go to Postgres API."""
    from auditor.config import Settings

    saved: dict = {}

    class FakeStore:
        enabled = True

        async def load_learned_playbooks(self):
            return dict(saved.get("frameworks") or {})

        async def save_learned_playbooks(self, frameworks):
            saved["frameworks"] = {fw: dict(entries) for fw, entries in frameworks.items()}
            return sum(len(v) for v in saved["frameworks"].values())

    settings = Settings(
        results_db_enabled=True,
        results_database_url="postgresql://u:p@localhost:5432/postgres",
        memory_enabled=True,
        memory_learn=True,
    )
    monkeypatch.setattr(
        "auditor.results_store.get_results_store",
        lambda _settings=None: FakeStore(),
    )

    memory_dir = tmp_path / "memory"
    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=memory_dir,
        learn=True,
        settings=settings,
    )
    mem.remember_tool(
        "ubuntu_cis_24_l2",
        "REQ-088",
        "ssh_run",
        {"command": "echo from-pg"},
        success=True,
    )
    assert "ubuntu_cis_24_l2" in saved.get("frameworks", {})
    assert "REQ-088" in saved["frameworks"]["ubuntu_cis_24_l2"]
    # Prefer Postgres — should not require JSON when save succeeds
    assert not (memory_dir / "learned_playbooks.json").is_file()

    mem2 = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=memory_dir,
        learn=True,
        settings=settings,
    )
    entry = mem2.get_entry("ubuntu_cis_24_l2", "REQ-088")
    assert entry is not None
    assert entry["tools"][0]["arguments"]["command"] == "echo from-pg"


def test_remember_skips_failures(tmp_path: Path):
    mem = PlaybookMemory(
        playbooks_dir=tmp_path / "empty_playbooks",
        memory_dir=tmp_path / "memory",
        learn=True,
    )
    (tmp_path / "empty_playbooks").mkdir()
    mem.remember_tool(
        "ubuntu_cis_24_l2",
        "REQ-001",
        "ssh_run",
        {"command": "id"},
        success=False,
    )
    assert mem.get_entry("ubuntu_cis_24_l2", "REQ-001") is None


def test_remember_persists_framework_without_seed_yaml(tmp_path: Path):
    """First-time frameworks (e.g. host_facts) must still land on disk."""
    playbooks = tmp_path / "empty_playbooks"
    playbooks.mkdir()
    memory_dir = tmp_path / "memory"
    mem = PlaybookMemory(
        playbooks_dir=playbooks,
        memory_dir=memory_dir,
        learn=True,
    )
    mem.remember_tool(
        "host_facts",
        "REQ-001",
        "ssh_run",
        {"command": "hostname -f"},
        success=True,
    )
    learned_path = memory_dir / "learned_playbooks.json"
    assert learned_path.is_file()
    payload = learned_path.read_text(encoding="utf-8")
    assert '"host_facts"' in payload
    assert "hostname -f" in payload

    mem2 = PlaybookMemory(
        playbooks_dir=playbooks,
        memory_dir=memory_dir,
        learn=True,
    )
    entry = mem2.get_entry("host_facts", "REQ-001")
    assert entry is not None
    assert entry["source"] == "learned"
    assert entry["tools"][0]["arguments"]["command"] == "hostname -f"

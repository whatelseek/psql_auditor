from pathlib import Path

from auditor.memory.playbook_store import PlaybookMemory


def test_loads_seed_playbooks_from_agents(tmp_path: Path):
    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        learn=False,
    )
    entry = mem.get_entry("ubuntu_cis", "REQ-002")
    assert entry is not None
    assert entry["tools"]
    assert entry["tools"][0]["name"] == "ssh_run"
    assert "PermitRootLogin" in entry["tools"][0]["arguments"]["command"]

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
    block = mem.format_prompt_block("ubuntu_cis", "REQ-002")
    assert "playbook memory" in block.lower()
    assert "ssh_run" in block
    assert "PermitRootLogin" in block


def test_host_prefixed_framework_uses_same_playbook_ns(tmp_path: Path):
    """Multi-host evidence keys must not break LangGraph namespace rules."""
    from auditor.memory.playbook_store import _memory_framework_id, _ns

    assert _memory_framework_id("10.200.29.78/ubuntu_cis") == "ubuntu_cis"
    assert _ns("10.200.29.78/ubuntu_cis") == ("playbooks", "ubuntu_cis")

    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=tmp_path / "memory",
        learn=True,
    )
    block = mem.format_prompt_block("10.200.29.78/ubuntu_cis", "REQ-002")
    assert "ssh_run" in block
    mem.remember_tool(
        "10.200.29.78/ubuntu_cis",
        "REQ-010",
        "ssh_run",
        {"command": "grep use_pty /etc/sudoers"},
        success=True,
    )
    entry = mem.get_entry("ubuntu_cis", "REQ-010")
    assert entry is not None
    assert entry["tools"][0]["name"] == "ssh_run"


def test_remember_tool_persists_learned_overlay(tmp_path: Path):
    memory_dir = tmp_path / "memory"
    mem = PlaybookMemory(
        playbooks_dir=Path("agents/playbooks"),
        memory_dir=memory_dir,
        learn=True,
    )
    mem.remember_tool(
        "ubuntu_cis",
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
    entry = mem2.get_entry("ubuntu_cis", "REQ-099")
    assert entry is not None
    assert entry["source"] == "learned"
    assert entry["tools"][0]["arguments"]["command"] == "echo learned-ok"


def test_remember_skips_failures(tmp_path: Path):
    mem = PlaybookMemory(
        playbooks_dir=tmp_path / "empty_playbooks",
        memory_dir=tmp_path / "memory",
        learn=True,
    )
    (tmp_path / "empty_playbooks").mkdir()
    mem.remember_tool(
        "ubuntu_cis",
        "REQ-001",
        "ssh_run",
        {"command": "id"},
        success=False,
    )
    assert mem.get_entry("ubuntu_cis", "REQ-001") is None

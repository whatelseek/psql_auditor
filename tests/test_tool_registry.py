"""INPUT-004 / TOOL-001 / EVID-001…003: tool registry + SSH vertical slice."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from auditor.config import Settings
from auditor.domain.tool_result import ToolProvenance, ToolResult
from auditor.evidence_store import EvidenceStore
from auditor.tool_registry import (
    ToolNotAuthorized,
    get_tool_registry,
    load_tool_registry,
    reset_tool_registry_cache,
)
from auditor.tools.ssh import invoke_ssh_read_file, invoke_ssh_run, take_last_tool_result


@pytest.fixture(autouse=True)
def _reset_registry_cache() -> None:
    reset_tool_registry_cache()
    yield
    reset_tool_registry_cache()


def _write_manifest(catalog: Path, name: str, payload: dict) -> Path:
    catalog.mkdir(parents=True, exist_ok=True)
    path = catalog / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _write_policy(root: Path, profile: str, payload: dict) -> Path:
    policy_dir = root / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    path = policy_dir / f"{profile}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _valid_ssh_manifest(tool_id: str = "ssh_run") -> dict:
    return {
        "id": tool_id,
        "version": "1.0.0",
        "title": tool_id,
        "description": "test",
        "transport": "ssh",
        "adapter": f"auditor.tools.ssh:invoke_{tool_id}",
        "capabilities": ["host.read"],
        "risk": "low",
        "readonly": True,
        "inventory_access": ["ssh"],
        "credential_source": "inventory:ssh",
        "blocked_operations": ["destructive_shell"],
        "timeout_seconds": 30,
        "max_output_bytes": 1000,
        "enabled": True,
        "profiles": ["poc_audit_v1"],
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
    }


@pytest.mark.unit
def test_load_valid_and_invalid_manifests(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(
        catalog,
        "broken",
        {
            "id": "broken_tool",
            # missing version / adapter / capabilities
            "transport": "ssh",
            "readonly": True,
            "enabled": True,
            "profiles": ["poc_audit_v1"],
        },
    )
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "broken_tool"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
        },
    )

    registry = load_tool_registry(root, profile="poc_audit_v1")
    catalog_rows = registry.catalog(executable_only=False)
    ids = {r.id for r in catalog_rows}
    assert "ssh_run" in ids
    assert "broken_tool" in ids

    ssh = registry.get("ssh_run")
    assert ssh is not None and ssh.executable
    assert registry.is_authorized("ssh_run")

    broken = registry.get("broken_tool")
    assert broken is not None
    assert not broken.executable
    assert not registry.is_authorized("broken_tool")
    # Invalid tools remain visible but are not bound.
    bound_names = {t.name for t in registry.bindable_langchain_tools()}
    assert "ssh_run" in bound_names
    assert "broken_tool" not in bound_names


@pytest.mark.unit
def test_unauthorized_tool_rejection(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    _write_manifest(root / "catalog", "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(root / "catalog", "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run"],  # ssh_read_file denied by omission
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 4000,
            "require_inventory_credentials": True,
        },
    )
    registry = load_tool_registry(root, profile="poc_audit_v1")
    assert registry.is_authorized("ssh_run")
    assert not registry.is_authorized("ssh_read_file")
    with pytest.raises(ToolNotAuthorized):
        registry.require_authorized("ssh_read_file")
    bound = {t.name for t in registry.bindable_langchain_tools()}
    assert bound == {"ssh_run"}


@pytest.mark.unit
def test_default_catalog_registers_ssh_tools() -> None:
    registry = get_tool_registry(refresh=True)
    assert registry.get("ssh_run") is not None
    assert registry.get("ssh_read_file") is not None
    assert registry.is_authorized("ssh_run")
    assert registry.is_authorized("ssh_read_file")
    assert registry.catalog_hash.startswith("tool-")
    assert registry.policy_hash.startswith("pol-")
    bound = {t.name for t in registry.bindable_langchain_tools(transports=("ssh",))}
    assert bound == {"ssh_run", "ssh_read_file"}


@pytest.mark.unit
def test_readonly_ssh_policy(tmp_path: Path) -> None:
    """Strict allow-list (no ssh_allow_all_commands) rejects composition."""
    from auditor.tools.ssh_policy import (
        is_approved_ssh_command,
        is_approved_ssh_read_path,
        ssh_command_denial_reason,
        ssh_read_path_denial_reason,
    )

    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    # Omit ssh_* keys → builtins; omit ssh_allow_all_commands → False.
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
        },
    )
    get_tool_registry(tools_dir=root, profile="poc_audit_v1", refresh=True)

    # Allow-list: exact approved commands only (no shell composition).
    assert is_approved_ssh_command("ss -lntp")
    assert is_approved_ssh_command("cat /etc/os-release")
    assert is_approved_ssh_command("uname -a")
    assert is_approved_ssh_command("hostnamectl")
    assert is_approved_ssh_command("hostname -f")
    assert is_approved_ssh_command("free -h")
    assert is_approved_ssh_command("lscpu")
    assert is_approved_ssh_command("lsblk -dn -o NAME")
    assert is_approved_ssh_command("ss -tulpen")
    assert is_approved_ssh_command("systemctl list-units --type=service --state=running")
    assert is_approved_ssh_command("rpm -qa")
    assert is_approved_ssh_command("dpkg-query -W")
    assert is_approved_ssh_command("smartctl -H /dev/sda")
    assert not is_approved_ssh_command("ss -lntp | grep 5432")
    assert not is_approved_ssh_command("bash -c 'uname'")
    assert not is_approved_ssh_command("rm -rf /var/lib/postgresql")
    assert not is_approved_ssh_command("apt-get install nginx")
    assert not is_approved_ssh_command("echo test")
    assert not is_approved_ssh_command("")
    assert "composition" in (ssh_command_denial_reason("uname -a; id") or "")

    assert is_approved_ssh_read_path("/etc/postgresql/16/main/postgresql.conf")
    assert is_approved_ssh_read_path("/etc/os-release")
    assert not is_approved_ssh_read_path("/etc/shadow")
    assert not is_approved_ssh_read_path("/home/user/.ssh/id_rsa")
    assert not is_approved_ssh_read_path("../etc/os-release")
    assert "sensitive" in (ssh_read_path_denial_reason("/etc/shadow") or "")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ssh_invocation_through_registry_denies_destructive(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
            "ssh_allowed_commands": ["uname -a"],
            "ssh_allowed_command_patterns": [],
        },
    )
    get_tool_registry(tools_dir=root, profile="poc_audit_v1", refresh=True)

    settings = Settings(
        _env_file=None,
        ssh_host="db.example",
        ssh_port=22,
        ssh_user="auditor",
        ssh_password="s3cret-password",
        ssh_strict_host_key=False,
    )
    result = await invoke_ssh_run("rm -rf /tmp/data", settings=settings)
    assert result.status == "denied"
    assert result.error and "allow-list" in result.error
    assert "s3cret-password" not in result.to_llm_text()
    assert "s3cret-password" not in json.dumps(result.to_evidence_record())
    assert result.arguments.get("command") == "rm -rf /tmp/data"
    assert result.target.host == "db.example"
    assert take_last_tool_result() is result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ssh_invocation_requires_inventory_target() -> None:
    settings = Settings(_env_file=None, ssh_host="", ssh_password="")
    result = await invoke_ssh_run("uname -a", settings=settings)
    assert result.status == "unauthorized"
    assert "not resolved" in (result.error or "")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ssh_invocation_normalized_result_with_mock_transport() -> None:
    settings = Settings(
        _env_file=None,
        ssh_host="10.0.0.5",
        ssh_port=22,
        ssh_user="audit",
        ssh_password="pw-should-not-leak",
        ssh_strict_host_key=False,
        ssh_command_timeout=5,
    )

    class _FakeResult:
        exit_status = 0
        stdout = "Linux\n"
        stderr = ""

    class _FakeConn:
        async def run(self, command: str, check: bool = False, timeout: float = 0) -> _FakeResult:
            assert "uname" in command
            return _FakeResult()

        async def __aenter__(self) -> _FakeConn:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    with patch("auditor.tools.ssh.asyncssh.connect", return_value=_FakeConn()):
        result = await invoke_ssh_run(
            "uname -a",
            settings=settings,
            provenance=ToolProvenance(
                client_id="client_demo",
                audit_run_id="arun_demo",
                framework_id="postgres_cis",
                requirement_id="REQ-001",
            ),
        )

    assert result.status == "ok"
    assert "Linux" in result.output
    assert result.exit_code == 0
    assert result.tool_id == "ssh_run"
    assert result.provenance.client_id == "client_demo"
    assert result.provenance.command_hash
    assert result.provenance.policy_decision == "allow"
    record = result.to_evidence_record()
    dumped = json.dumps(record)
    assert "pw-should-not-leak" not in dumped
    assert record["provenance"]["framework_id"] == "postgres_cis"
    assert record["schema"] == "tool_result.v1"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ssh_read_file_through_adapter() -> None:
    settings = Settings(
        _env_file=None,
        ssh_host="host1",
        ssh_user="u",
        ssh_password="secret",
        ssh_strict_host_key=False,
    )

    class _FakeResult:
        exit_status = 0
        stdout = "listen_addresses = '*'\n"
        stderr = ""

    class _FakeConn:
        async def run(self, command: str, check: bool = False, timeout: float = 0) -> _FakeResult:
            assert "head -c" in command
            assert "postgresql.conf" in command
            return _FakeResult()

        async def __aenter__(self) -> _FakeConn:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    with patch("auditor.tools.ssh.asyncssh.connect", return_value=_FakeConn()):
        result = await invoke_ssh_read_file("/etc/postgresql/postgresql.conf", settings=settings)

    assert result.status == "ok"
    assert result.tool_id == "ssh_read_file"
    assert "listen_addresses" in result.output
    assert result.arguments.get("path") == "/etc/postgresql/postgresql.conf"


@pytest.mark.unit
def test_evidence_store_writes_normalized_provenance(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path, run_id="run_tools")
    store.write_run_meta(client_id="client_a", audit_run_id="arun_a000000000001")
    tool_result = ToolResult(
        status="ok",
        output="exit_code=0\nstdout:\nok",
        error=None,
        tool_id="ssh_run",
        tool_version="1.0.0",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        provenance=ToolProvenance(
            policy_decision="allow",
            command_hash="abcd",
        ),
        arguments={"command": "uname -a", "password": "should-redact"},
    )
    path = store.write_tool_result(
        "postgres_cis",
        "REQ-001",
        "ssh_run",
        {"command": "uname -a", "password": "should-redact"},
        "exit_code=0\nstdout:\nok",
        tool_result=tool_result,
        client_id="client_a",
        audit_run_id="arun_a000000000001",
        requirement_title="Hostname",
        tool_catalog_hash="tool-deadbeef",
        capability_policy_hash="pol-cafebabe",
    )
    sidecar = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    assert sidecar["schema"] == "tool_result.v1"
    assert sidecar["tool_id"] == "ssh_run"
    assert sidecar["provenance"]["client_id"] == "client_a"
    assert sidecar["provenance"]["audit_run_id"] == "arun_a000000000001"
    assert sidecar["provenance"]["framework_id"] == "postgres_cis"
    assert sidecar["provenance"]["requirement_id"] == "REQ-001"
    assert sidecar["provenance"]["tool_catalog_hash"] == "tool-deadbeef"
    assert "should-redact" not in path.read_text(encoding="utf-8")
    assert sidecar["arguments"]["password"] == "***REDACTED***"


@pytest.mark.unit
def test_audit_plan_pins_tool_hashes() -> None:
    from auditor.domain.inventory import (
        ClientInventory,
        InventoryHost,
        InventoryVersion,
    )
    from auditor.inventory.plan import generate_audit_plan

    inventory = ClientInventory(
        client_id="client_plan",
        version=InventoryVersion(
            version_id="inv-aaaaaaaaaaaa",
            content_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            source_format="markdown",
            source_path="PlanCo/INVENTORY.md",
            recorded_at="2026-01-01T00:00:00Z",
        ),
        hosts=(
            InventoryHost(
                host_id="h1",
                address="10.0.0.1",
                hostname="h1",
                os_family="linux",
            ),
        ),
    )
    plan = generate_audit_plan(inventory, detections=[])
    assert plan.tool_catalog_hash.startswith("tool-")
    assert plan.capability_policy_hash.startswith("pol-")


@pytest.mark.unit
def test_audit_run_scope_pins_tool_hashes(tmp_path: Path) -> None:
    from auditor.audit_registry import AuditRegistry

    registry = AuditRegistry(tmp_path / "registry.sqlite")
    run = registry.create_run(
        client_id="client_toolreg0001",
        scope={"frameworks": ["postgres_cis"]},
    )
    assert run.scope.get("tool_catalog_hash", "").startswith("tool-")
    assert run.scope.get("capability_policy_hash", "").startswith("pol-")


@pytest.mark.unit
def test_graph_binds_registry_ssh_tools_only() -> None:
    from auditor.graph import AuditorGraph, _registry_ssh_tools

    settings = Settings(
        _env_file=None,
        agents_dir=Path("agents"),
        memory_enabled=False,
        litellm_base_url="http://localhost:9",
    )
    names = {t.name for t in _registry_ssh_tools()}
    assert names == {"ssh_run", "ssh_read_file"}
    graph = AuditorGraph(settings=settings)
    assert "ssh_run" in graph.tools_by_name
    assert "ssh_read_file" in graph.tools_by_name


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execute_tool_calls_persists_ssh_tool_result(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from auditor.workflows.tool_execution import execute_tool_calls

    tools_root = tmp_path / "tools"
    catalog = tools_root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(
        tools_root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
            "ssh_allowed_commands": ["uname -a"],
            "ssh_allowed_command_patterns": [],
        },
    )
    get_tool_registry(tools_dir=tools_root, profile="poc_audit_v1", refresh=True)

    store = EvidenceStore(tmp_path / "evidence", run_id="run_exec")
    store.write_run_meta(client_id="client_x", audit_run_id="arun_x000000000001")

    class _Tool:
        name = "ssh_run"

        async def ainvoke(self, args: dict) -> str:
            # execute_tool_calls() may reload the default registry; re-pin strict policy.
            get_tool_registry(tools_dir=tools_root, profile="poc_audit_v1")
            result = await invoke_ssh_run(
                str(args.get("command") or ""),
                settings=Settings(
                    _env_file=None,
                    ssh_host="h",
                    ssh_user="u",
                    ssh_password="hidden-secret",
                    ssh_strict_host_key=False,
                ),
            )
            return result.to_llm_text()

    runtime = SimpleNamespace(
        tools_by_name={"ssh_run": _Tool()},
        settings=Settings(_env_file=None, max_tool_output_chars=2000, memory_learn=False),
        playbooks=None,
    )
    messages = await execute_tool_calls(
        runtime,  # type: ignore[arg-type]
        [{"name": "ssh_run", "args": {"command": "rm -rf /"}, "id": "c1"}],
        framework_id="postgres_cis",
        req_id="REQ-002",
        requirement_title="Destructive gate",
        store=store,
    )
    assert messages[0].content.startswith("Tool denied:")
    sidecar = json.loads(
        (store.root / "postgres_cis" / "REQ-002" / "001_ssh_run.json").read_text(encoding="utf-8")
    )
    assert sidecar["status"] == "denied"
    assert sidecar["provenance"]["requirement_id"] == "REQ-002"
    assert "hidden-secret" not in json.dumps(sidecar)


@pytest.mark.unit
def test_registry_fail_closed_no_legacy_ssh_fallback(tmp_path: Path) -> None:
    """Empty/unauthorized registry must not fall back to unbound SSH tools."""
    from auditor.graph import _registry_ssh_tools
    from auditor.tool_registry import load_tool_registry, reset_tool_registry_cache

    root = tmp_path / "tools"
    (root / "catalog").mkdir(parents=True)
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": [],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 1000,
            "require_inventory_credentials": True,
        },
    )
    # Point the process cache at the empty authorized set via monkeypatch of loader.
    reset_tool_registry_cache()
    empty = load_tool_registry(root, profile="poc_audit_v1")
    assert empty.bindable_langchain_tools(transports=("ssh",)) == []

    with patch("auditor.graph.get_tool_registry", return_value=empty):
        assert _registry_ssh_tools() == []


@pytest.mark.unit
def test_duplicate_tool_ids_all_non_executable(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    catalog = root / "catalog"
    payload = _valid_ssh_manifest("ssh_run")
    _write_manifest(catalog, "ssh_run", payload)
    _write_manifest(catalog, "ssh_run_dup", payload)
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 1000,
            "require_inventory_credentials": True,
        },
    )
    registry = load_tool_registry(root, profile="poc_audit_v1")
    conflicting = [t for t in registry.list_tools() if t.id == "ssh_run"]
    assert len(conflicting) >= 2
    assert all(not t.executable for t in conflicting)
    assert not registry.is_authorized("ssh_run")
    assert registry.bindable_langchain_tools() == []


@pytest.mark.unit
def test_malformed_numeric_and_boolean_fields_are_validation_issues(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    catalog = root / "catalog"
    payload = _valid_ssh_manifest("ssh_run")
    payload["timeout_seconds"] = "not-a-number"
    payload["max_output_bytes"] = {"nested": True}
    payload["readonly"] = "sometimes"
    payload["enabled"] = 2
    _write_manifest(catalog, "ssh_run", payload)
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": "yes-please",
            "allowed_tools": ["ssh_run"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": "plenty",
            "require_inventory_credentials": True,
        },
    )
    # Must not crash — malformed fields become validation issues.
    registry = load_tool_registry(root, profile="poc_audit_v1")
    tool = registry.get("ssh_run")
    assert tool is not None
    assert not tool.executable
    codes = {i.code for i in tool.issues}
    assert "invalid_numeric_field" in codes
    assert "invalid_boolean_field" in codes
    assert registry.policy is not None
    assert not registry.policy.executable


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ssh_nonzero_exit_maps_to_error_status() -> None:
    settings = Settings(
        _env_file=None,
        ssh_host="10.0.0.8",
        ssh_user="audit",
        ssh_password="pw",
        ssh_strict_host_key=False,
    )

    class _FakeResult:
        exit_status = 2
        stdout = "partial"
        stderr = "not found"

    class _FakeConn:
        async def run(self, command: str, check: bool = False, timeout: float = 0) -> _FakeResult:
            return _FakeResult()

        async def __aenter__(self) -> _FakeConn:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    with patch("auditor.tools.ssh.asyncssh.connect", return_value=_FakeConn()):
        result = await invoke_ssh_run("uname -a", settings=settings)

    assert result.status == "error"
    assert result.exit_code == 2
    assert result.error and "non-zero" in result.error
    assert "partial" in result.output


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ssh_read_file_blocks_sensitive_paths_and_redacts_output() -> None:
    settings = Settings(
        _env_file=None,
        ssh_host="host1",
        ssh_user="u",
        ssh_password="super-secret-pw",
        ssh_strict_host_key=False,
    )
    denied = await invoke_ssh_read_file("/etc/shadow", settings=settings)
    assert denied.status == "denied"
    assert "path allow-list" in (denied.error or "")

    class _FakeResult:
        exit_status = 0
        stdout = "password=super-secret-pw\nlisten_addresses='*'\n"
        stderr = "token: abc123"

    class _FakeConn:
        async def run(self, command: str, check: bool = False, timeout: float = 0) -> _FakeResult:
            return _FakeResult()

        async def __aenter__(self) -> _FakeConn:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    with patch("auditor.tools.ssh.asyncssh.connect", return_value=_FakeConn()):
        result = await invoke_ssh_read_file(
            "/etc/postgresql/16/main/postgresql.conf",
            settings=settings,
        )

    assert result.status == "ok"
    assert "super-secret-pw" not in result.output
    assert "super-secret-pw" not in result.to_llm_text()
    assert "***REDACTED***" in result.output


@pytest.mark.unit
def test_stale_tool_snapshot_rejects_confirm_and_invoke(tmp_path: Path) -> None:
    from auditor.domain.audit_plan import AuditPlan, AuditPlanSummary, PlanConfirmationRejected
    from auditor.inventory.plan import assert_plan_matches_tool_registry
    from auditor.tool_registry import ToolSnapshotStale, assert_tool_snapshot_current

    with pytest.raises(ToolSnapshotStale):
        assert_tool_snapshot_current(
            tool_catalog_hash="tool-deadbeefdead",
            capability_policy_hash="pol-cafebabe00",
        )

    plan = AuditPlan(
        plan_id="plan-test",
        client_id="client_plan",
        inventory_version_id="inv-aaaaaaaaaaaa",
        inventory_content_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        tool_catalog_hash="tool-stale000000",
        capability_policy_hash="pol-stale000000",
        summary=AuditPlanSummary(
            total_hosts=0,
            total_audit_target_instances=0,
        ),
        created_at="2026-01-01T00:00:00Z",
    )

    with pytest.raises(PlanConfirmationRejected) as exc:
        assert_plan_matches_tool_registry(plan)
    assert exc.value.code in {"tool_snapshot_stale", "audit_plan_stale"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_invoke_rejects_stale_provenance_hashes() -> None:
    settings = Settings(
        _env_file=None,
        ssh_host="h",
        ssh_user="u",
        ssh_password="x",
        ssh_strict_host_key=False,
    )
    result = await invoke_ssh_run(
        "uname -a",
        settings=settings,
        provenance=ToolProvenance(
            tool_catalog_hash="tool-stalehash01",
            capability_policy_hash="pol-stalehash01",
        ),
    )
    assert result.status == "unauthorized"
    assert "mismatch" in (result.error or "").lower() or "stale" in (result.error or "").lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execute_tool_calls_rejects_stale_run_snapshot(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from auditor.workflows.tool_execution import execute_tool_calls

    store = EvidenceStore(tmp_path, run_id="run_stale")
    store.write_run_meta(
        client_id="client_x",
        audit_run_id="arun_x000000000002",
        tool_catalog_hash="tool-stalehash99",
        capability_policy_hash="pol-stalehash99",
    )

    class _Tool:
        name = "ssh_run"
        called = False

        async def ainvoke(self, args: dict) -> str:
            self.called = True
            return "should-not-run"

    tool = _Tool()
    runtime = SimpleNamespace(
        tools_by_name={"ssh_run": tool},
        settings=Settings(_env_file=None, max_tool_output_chars=2000, memory_learn=False),
        playbooks=None,
    )
    messages = await execute_tool_calls(
        runtime,  # type: ignore[arg-type]
        [{"name": "ssh_run", "args": {"command": "uname -a"}, "id": "c1"}],
        framework_id="postgres_cis",
        req_id="REQ-009",
        store=store,
    )
    assert not tool.called
    assert messages[0].content.startswith("Tool unauthorized:")


@pytest.mark.unit
def test_registry_cache_isolates_directories(tmp_path: Path) -> None:
    """Process cache must not mix catalogs from different tools directories."""
    root_a = tmp_path / "tools_a"
    root_b = tmp_path / "tools_b"
    for root, desc in ((root_a, "catalog-a"), (root_b, "catalog-b")):
        catalog = root / "catalog"
        payload_run = _valid_ssh_manifest("ssh_run")
        payload_run["description"] = desc
        _write_manifest(catalog, "ssh_run", payload_run)
        _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
        _write_policy(
            root,
            "poc_audit_v1",
            {
                "version": "1.0.0",
                "profile": "poc_audit_v1",
                "readonly_required": True,
                "allowed_tools": ["ssh_run", "ssh_read_file"],
                "denied_tools": [],
                "allowed_transports": ["ssh"],
                "max_output_chars": 6000,
                "require_inventory_credentials": True,
            },
        )

    registry_a = get_tool_registry(tools_dir=root_a, profile="poc_audit_v1")
    registry_b = get_tool_registry(tools_dir=root_b, profile="poc_audit_v1")
    assert registry_a is not registry_b
    assert registry_a.catalog_hash != registry_b.catalog_hash
    assert get_tool_registry(tools_dir=root_a, profile="poc_audit_v1") is registry_a


@pytest.mark.unit
def test_validate_rejects_tampered_injected_adapter(tmp_path: Path) -> None:
    """On-disk snapshot must win over mutated in-memory adapter fields."""
    from dataclasses import replace

    from auditor.tool_registry import (
        RuntimeToolCatalogError,
        load_tool_registry,
        validate_runtime_tool_registry,
    )

    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
        },
    )
    registry = load_tool_registry(root, profile="poc_audit_v1")
    manifest = registry.get("ssh_run")
    assert manifest is not None
    registry.tools["ssh_run"] = replace(
        manifest,
        adapter="auditor.tools.ssh:invoke_ssh_read_file",
    )
    with pytest.raises(RuntimeToolCatalogError) as exc_info:
        validate_runtime_tool_registry(
            registry,
            tools_dir=root,
            expected_profile="poc_audit_v1",
        )
    assert exc_info.value.code == "registry_snapshot_mismatch"
    assert exc_info.value.tool_id == "ssh_run"
    assert "invoke_ssh_read_file" not in str(exc_info.value)


@pytest.mark.unit
def test_snapshot_rejects_cleared_validation_issues(tmp_path: Path) -> None:
    """issues=() on an invalid on-disk manifest must not pass snapshot equality."""
    from dataclasses import replace

    from auditor.tool_registry import (
        RuntimeToolCatalogError,
        load_tool_registry,
        validate_runtime_tool_registry,
    )

    root = tmp_path / "tools"
    catalog = root / "catalog"
    payload = _valid_ssh_manifest("ssh_run")
    payload["timeout_seconds"] = "not-a-number"
    _write_manifest(catalog, "ssh_run", payload)
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
        },
    )
    registry = load_tool_registry(root, profile="poc_audit_v1")
    manifest = registry.get("ssh_run")
    assert manifest is not None
    assert any(i.level == "error" for i in manifest.issues)
    registry.tools["ssh_run"] = replace(manifest, issues=(), enabled=True)
    with pytest.raises(RuntimeToolCatalogError) as exc_info:
        validate_runtime_tool_registry(
            registry,
            tools_dir=root,
            expected_profile="poc_audit_v1",
        )
    assert exc_info.value.code == "registry_snapshot_mismatch"
    assert exc_info.value.tool_id == "ssh_run"


@pytest.mark.unit
def test_normalize_manifest_source_path_none_equals_empty() -> None:
    """None and empty source_path must compare equal after normalization."""
    from dataclasses import replace

    from auditor.tool_registry import (
        ToolManifest,
        _normalize_manifest_source_path,
        _required_manifest_snapshot_matches,
    )

    base = ToolManifest(
        id="ssh_run",
        version="1.0.0",
        title="SSH Run",
        description="",
        transport="ssh",
        adapter="ssh_run",
        capabilities=("exec",),
        risk="low",
        readonly=True,
        inventory_access=(),
        credential_source="inventory",
        blocked_operations=(),
        timeout_seconds=30,
        max_output_bytes=1024,
        enabled=True,
        profiles=("poc_audit_v1",),
        input_schema={},
        output_schema={},
    )
    with_none = replace(base, source_path=None)  # type: ignore[arg-type]
    with_empty = replace(base, source_path="")
    assert with_none.source_path is None
    assert with_empty.source_path == ""
    assert _normalize_manifest_source_path(with_none).source_path == ""
    assert _normalize_manifest_source_path(with_empty).source_path == ""
    assert _required_manifest_snapshot_matches(with_none, with_empty)


@pytest.mark.unit
def test_ssh_allowlist_from_capability_policy(tmp_path: Path) -> None:
    """ssh_allowed_commands in policy JSON drive approval (empty = deny-all)."""
    from auditor.tool_registry import get_tool_registry, reset_tool_registry_cache
    from auditor.tools.ssh_policy import is_approved_ssh_command, ssh_command_denial_reason

    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))

    # Explicit empty lists → deny-all (fail closed).
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
            "ssh_allowed_commands": [],
            "ssh_allowed_command_patterns": [],
        },
    )
    reset_tool_registry_cache()
    get_tool_registry(tools_dir=root, profile="poc_audit_v1", refresh=True)
    assert not is_approved_ssh_command("hostname")
    assert ssh_command_denial_reason("hostname")

    # Policy-only exact command (not relying on builtins).
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
            "ssh_allowed_commands": ["hostnamectl", "mycustom-probe --ok"],
            "ssh_allowed_command_patterns": [r"^sysctl\s+[A-Za-z0-9._*-]+$"],
        },
    )
    reset_tool_registry_cache()
    pol = get_tool_registry(tools_dir=root, profile="poc_audit_v1", refresh=True).policy
    assert pol is not None
    assert pol.ssh_allowed_commands == ("hostnamectl", "mycustom-probe --ok")
    assert is_approved_ssh_command("hostnamectl")
    assert is_approved_ssh_command("mycustom-probe --ok")
    assert is_approved_ssh_command("sysctl net.ipv4.ip_forward")
    assert not is_approved_ssh_command("hostname")  # not in this policy
    assert not is_approved_ssh_command("mycustom-probe --ok | cat")


@pytest.mark.unit
def test_ssh_allow_all_commands_poc_flag(tmp_path: Path) -> None:
    """ssh_allow_all_commands approves arbitrary (including composed) commands."""
    from auditor.tool_registry import get_tool_registry, reset_tool_registry_cache
    from auditor.tools.ssh_policy import is_approved_ssh_command, ssh_command_denial_reason

    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(
        root,
        "poc_audit_v1",
        {
            "version": "1.0.0",
            "profile": "poc_audit_v1",
            "readonly_required": True,
            "allowed_tools": ["ssh_run", "ssh_read_file"],
            "denied_tools": [],
            "allowed_transports": ["ssh"],
            "max_output_chars": 6000,
            "require_inventory_credentials": True,
            "ssh_allow_all_commands": True,
            "ssh_allowed_commands": [],
            "ssh_allowed_command_patterns": [],
        },
    )
    reset_tool_registry_cache()
    get_tool_registry(tools_dir=root, profile="poc_audit_v1", refresh=True)
    assert is_approved_ssh_command("hostnamectl")
    assert is_approved_ssh_command("ss -lntp | grep 5432")
    assert is_approved_ssh_command("echo test")
    assert ssh_command_denial_reason("anything goes") is None
    assert not is_approved_ssh_command("")

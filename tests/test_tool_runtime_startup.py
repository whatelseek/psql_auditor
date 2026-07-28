"""TOOL001-07: runtime tool catalog packaging and startup validation."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from auditor.application_runtime import ApplicationRuntime, RuntimeStartupError
from auditor.config import Settings
from auditor.domain.audit_request import POC_TOOL_PROFILE
from auditor.tool_registry import (
    REQUIRED_POC_SSH_TOOL_IDS,
    RuntimeToolCatalogError,
    get_tool_registry,
    load_tool_registry,
    reset_tool_registry_cache,
    validate_runtime_tool_registry,
)


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
        "profiles": [POC_TOOL_PROFILE],
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
    }


def _poc_policy(**overrides: object) -> dict:
    payload: dict = {
        "version": "1.0.0",
        "profile": POC_TOOL_PROFILE,
        "readonly_required": True,
        "allowed_tools": ["ssh_run", "ssh_read_file"],
        "denied_tools": [],
        "allowed_transports": ["ssh"],
        "max_output_chars": 6000,
        "require_inventory_credentials": True,
    }
    payload.update(overrides)
    return payload


def _seed_valid_tools(root: Path) -> Path:
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(root, POC_TOOL_PROFILE, _poc_policy())
    return root


def _settings(tmp_path: Path, tools_dir: Path) -> Settings:
    return Settings(
        _env_file=None,
        evidence_dir=tmp_path / "artifacts",
        agents_dir=Path("agents"),
        tools_dir=tools_dir,
        memory_enabled=False,
        litellm_base_url="http://localhost:9",
        model_id="tool001-07",
    )


@pytest.mark.asyncio
async def test_valid_runtime_startup(tmp_path: Path) -> None:
    tools = _seed_valid_tools(tmp_path / "tools")
    runtime = ApplicationRuntime(_settings(tmp_path, tools))
    await runtime.start()
    try:
        assert runtime.tool_registry is not None
        assert runtime.tool_registry.is_authorized("ssh_run")
        assert runtime.tool_registry.is_authorized("ssh_read_file")
        assert runtime.graph is not None
        assert runtime.graph.tools_by_name["ssh_run"].name == "ssh_run"
        assert runtime.graph.tools_by_name["ssh_read_file"].name == "ssh_read_file"
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_missing_tools_directory_fails_startup(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-tools"
    runtime = ApplicationRuntime(_settings(tmp_path, missing))
    with pytest.raises(RuntimeStartupError) as exc_info:
        await runtime.start()
    message = str(exc_info.value)
    assert "tools directory missing" in message
    assert "PASSWORD" not in message
    assert "sk-" not in message
    assert "ssh_password" not in message
    assert runtime.graph is None


@pytest.mark.asyncio
async def test_missing_policy_fails_startup(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    runtime = ApplicationRuntime(_settings(tmp_path, root))
    with pytest.raises(RuntimeStartupError):
        await runtime.start()


@pytest.mark.asyncio
async def test_unknown_allowed_tool_fails_before_graph(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    catalog = root / "catalog"
    _write_manifest(catalog, "ssh_run", _valid_ssh_manifest("ssh_run"))
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(
        root,
        POC_TOOL_PROFILE,
        _poc_policy(allowed_tools=["ssh_run", "missing_tool"]),
    )
    graph_calls: list[object] = []

    def boom(_runtime: ApplicationRuntime):
        graph_calls.append(_runtime)
        raise AssertionError("graph must not be constructed")

    runtime = ApplicationRuntime(_settings(tmp_path, root), graph_factory=boom)
    with pytest.raises(RuntimeStartupError) as exc_info:
        await runtime.start()
    assert graph_calls == []
    assert "missing_tool" in str(exc_info.value)


@pytest.mark.asyncio
async def test_required_tool_denied_fails_startup(tmp_path: Path) -> None:
    root = _seed_valid_tools(tmp_path / "tools")
    _write_policy(
        root,
        POC_TOOL_PROFILE,
        _poc_policy(denied_tools=["ssh_run"]),
    )
    runtime = ApplicationRuntime(_settings(tmp_path, root))
    with pytest.raises(RuntimeStartupError) as exc_info:
        await runtime.start()
    assert "ssh_run" in str(exc_info.value)


@pytest.mark.asyncio
async def test_non_bindable_adapter_fails_startup(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    catalog = root / "catalog"
    payload = _valid_ssh_manifest("ssh_run")
    payload["adapter"] = "auditor.tools.ssh:definitely_missing_adapter"
    _write_manifest(catalog, "ssh_run", payload)
    _write_manifest(catalog, "ssh_read_file", _valid_ssh_manifest("ssh_read_file"))
    _write_policy(root, POC_TOOL_PROFILE, _poc_policy())
    runtime = ApplicationRuntime(_settings(tmp_path, root))
    with pytest.raises(RuntimeStartupError) as exc_info:
        await runtime.start()
    assert "ssh_run" in str(exc_info.value)


@pytest.mark.asyncio
async def test_bound_name_mismatch_fails_startup(tmp_path: Path) -> None:
    root = _seed_valid_tools(tmp_path / "tools")
    registry = load_tool_registry(root, profile=POC_TOOL_PROFILE)

    class _Mismatched:
        name = "different_name"

    with patch(
        "auditor.tool_registry._resolve_langchain_tool",
        return_value=_Mismatched(),
    ):
        with pytest.raises(RuntimeToolCatalogError) as exc_info:
            validate_runtime_tool_registry(
                registry,
                required_tool_ids=REQUIRED_POC_SSH_TOOL_IDS,
                tools_dir=root,
            )
    assert exc_info.value.code == "bound_name_mismatch"
    assert exc_info.value.tool_id in REQUIRED_POC_SSH_TOOL_IDS

    runtime = ApplicationRuntime(_settings(tmp_path, root))
    with patch(
        "auditor.tool_registry._resolve_langchain_tool",
        return_value=_Mismatched(),
    ):
        with pytest.raises(RuntimeStartupError):
            await runtime.start()


@pytest.mark.asyncio
async def test_graph_receives_owned_registry(tmp_path: Path) -> None:
    tools = _seed_valid_tools(tmp_path / "tools")
    fake = SimpleNamespace(
        is_authorized=lambda _tid: True,
        bindable_langchain_tools=lambda **_kwargs: [],
        catalog_hash="tool-fake",
        policy_hash="pol-fake",
    )
    seen: dict[str, object] = {}

    class _FakeGraph:
        async def aclose_runtime_resources(self, timeout: float = 10.0) -> None:
            return None

    def factory(runtime: ApplicationRuntime):
        seen["registry"] = runtime.tool_registry
        return _FakeGraph()

    runtime = ApplicationRuntime(
        _settings(tmp_path, tools),
        tool_registry=fake,  # type: ignore[arg-type]
        graph_factory=factory,
    )
    await runtime.start()
    try:
        assert seen["registry"] is fake
        assert runtime.tool_registry is fake
    finally:
        await runtime.close()


@pytest.mark.unit
def test_registry_path_isolation(tmp_path: Path) -> None:
    root_a = _seed_valid_tools(tmp_path / "tools_a")
    root_b = tmp_path / "tools_b"
    catalog_b = root_b / "catalog"
    _write_manifest(catalog_b, "ssh_run", _valid_ssh_manifest("ssh_run"))
    read_payload = _valid_ssh_manifest("ssh_read_file")
    read_payload["description"] = "different-catalog-b"
    _write_manifest(catalog_b, "ssh_read_file", read_payload)
    _write_policy(root_b, POC_TOOL_PROFILE, _poc_policy())

    registry_a = get_tool_registry(tools_dir=root_a, profile=POC_TOOL_PROFILE)
    registry_b = get_tool_registry(tools_dir=root_b, profile=POC_TOOL_PROFILE)
    assert registry_a is not registry_b
    assert registry_a.catalog_hash != registry_b.catalog_hash

    again_a = get_tool_registry(tools_dir=root_a, profile=POC_TOOL_PROFILE)
    assert again_a is registry_a
    again_b = get_tool_registry(tools_dir=root_b, profile=POC_TOOL_PROFILE)
    assert again_b is registry_b


@pytest.mark.unit
def test_compose_mounts_tools_readonly() -> None:
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        capture_output=True,
        text=True,
    )
    config = result.stdout
    assert "TOOLS_DIR: /app/tools" in config or "TOOLS_DIR=/app/tools" in config
    assert "/app/tools" in config
    lowered = config.lower()
    assert "tools" in lowered
    assert "read_only: true" in lowered or ":ro" in config

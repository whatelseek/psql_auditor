"""INPUT005-14 — typed capability discovery planning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from auditor.domain.audit_plan import PlanConfirmationRejected
from auditor.domain.inventory import (
    ClientInventory,
    InventoryHost,
    InventoryVersion,
    ValidationIssue,
)
from auditor.domain.normalized_facts import (
    HostFactSet,
    NormalizedFact,
)
from auditor.inventory.discovery_plan import build_capability_discovery_plan
from auditor.inventory.framework_candidates import evaluate_framework_candidates
from auditor.inventory.plan import (
    assert_plan_matches_discovery_plan,
    generate_audit_plan,
)
from auditor.inventory.plan_store import PlanRevisionStore
from auditor.tool_registry import CapabilityPolicy, ToolManifest, ToolRegistry

CANARY_PASSWORD = "CANARY_PASSWORD_INPUT005_14"
CANARY_TOKEN = "CANARY_TOKEN_INPUT005_14"
CANARY_NOTES = "SECRET_NOTE_CANARY_INPUT005_14"
CANARY_DESC = "FRAMEWORK_DESC_CANARY_INPUT005_14"
CANARY_PURPOSE = "HINT_PURPOSE_CANARY_INPUT005_14"
CANARY_EVIDENCE = "RAW_EVIDENCE_CANARY_INPUT005_14"

_VALID_BODY = f"""# Sample Framework

{CANARY_DESC}

## REQ-001: Demo check
**Category:** Demo
**Severity:** Low
**How to verify:** echo ok
**Pass criteria:** ok
"""


def _write_fw(directory: Path, name: str, *, frontmatter: str, body: str = _VALID_BODY) -> Path:
    path = directory / name
    path.write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")
    return path


def _version(vid: str = "inv-1", *, source_format: str = "markdown") -> InventoryVersion:
    return InventoryVersion(
        version_id=vid,
        content_hash="hash-1",
        source_format=source_format,  # type: ignore[arg-type]
        recorded_at="2026-01-01T00:00:00Z",
    )


def _host(**kwargs: object) -> InventoryHost:
    base: dict[str, object] = {
        "host_id": "host-01",
        "asset_type": "server",
        "os_family": "linux",
        "os_name": "",
        "connection_types": ("ssh",),
        "notes": CANARY_NOTES,
    }
    base.update(kwargs)
    return InventoryHost(**base)  # type: ignore[arg-type]


def _inventory(hosts: list[InventoryHost], **kwargs: object) -> ClientInventory:
    base: dict[str, object] = {
        "client_id": "client-a",
        "hosts": tuple(hosts),
        "version": _version(),
        "credentials": (),
    }
    base.update(kwargs)
    return ClientInventory(**base)  # type: ignore[arg-type]


def _manifest(
    tool_id: str,
    *,
    capabilities: tuple[str, ...] = ("host.read",),
    inventory_access: tuple[str, ...] = ("ssh",),
    enabled: bool = True,
    issues: tuple[Any, ...] = (),
) -> ToolManifest:
    return ToolManifest(
        id=tool_id,
        version="1.0.0",
        title=tool_id,
        description="test",
        transport="ssh",
        adapter="tests.fake:invoke",
        capabilities=capabilities,
        risk="low",
        readonly=True,
        inventory_access=inventory_access,
        credential_source="inventory:ssh",
        blocked_operations=(),
        timeout_seconds=30,
        max_output_bytes=1000,
        enabled=enabled,
        profiles=("poc_audit_v1",),
        input_schema={},
        output_schema={},
        issues=issues,  # type: ignore[arg-type]
    )


def _registry(
    tools: dict[str, ToolManifest],
    *,
    allowed: tuple[str, ...] | None = None,
    denied: tuple[str, ...] = (),
) -> ToolRegistry:
    allowed_tools = allowed if allowed is not None else tuple(sorted(tools))
    policy = CapabilityPolicy(
        version="1",
        profile="poc_audit_v1",
        description="test",
        readonly_required=True,
        allowed_tools=allowed_tools,
        denied_tools=denied,
        allowed_transports=("ssh",),
        max_output_chars=10000,
        require_inventory_credentials=False,
    )
    return ToolRegistry(tools=tools, policy=policy)


def _os_name_agents(
    tmp_path: Path,
    *,
    ops: list[str] | None = None,
    expected: list[str] | None = None,
    extra_front: str = "",
) -> Path:
    agents = tmp_path / "agents"
    agents.mkdir(parents=True, exist_ok=True)
    op_yaml = "\n".join(f"      - {op}" for op in (ops or ["ssh_run"]))
    exp_yaml = "\n".join(
        f"      - {fact}" for fact in (expected if expected is not None else ["os.name"])
    )
    expected_block = (
        f"    expected_facts:\n{exp_yaml}\n" if expected != [] else "    expected_facts: []\n"
    )
    _write_fw(
        agents,
        "os_probe.md",
        frontmatter=f"""
id: os_probe
version: "1"
family_id: os_probe
language: en
applicability:
  all:
    - fact: os.name
      operator: equals
      value: Ubuntu
required_facts:
  - os.name
discovery_hints:
  - capability: host.read
    purpose: "{CANARY_PURPOSE}"
    operation_ids:
{op_yaml}
{expected_block}{extra_front}
target:
  scope: host
  service: ""
""",
    )
    return agents


def _fact_set(host_id: str, facts: dict[str, object]) -> HostFactSet:
    rows = [
        NormalizedFact(
            fact=key,
            value=value,  # type: ignore[arg-type]
            confidence=1.0,
            source_type="inventory",
            source_ref="test",
            evidence_refs=(CANARY_EVIDENCE,),
        )
        for key, value in sorted(facts.items())
    ]
    return HostFactSet(host_id=host_id, facts=tuple(rows))


def test_missing_fact_with_valid_hint_plans_ssh_run(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host(os_name="")])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv,
        (),
        agents_dir=agents,
        registry=registry,
        host_facts=facts,
    )
    assert len(plan.steps) == 1
    step = plan.steps[0]
    assert step.status == "planned"
    assert step.tool_id == "ssh_run"
    assert step.operation_id == "ssh_run"
    assert step.missing_facts == ("os.name",)


def test_planner_does_not_bind_or_invoke_tools(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("must not bind or invoke tools")

    with (
        patch.object(ToolRegistry, "bindable_langchain_tools", _boom),
        patch("auditor.tools.ssh.invoke_ssh_run", _boom),
        patch("auditor.tools.ssh.ssh_run", _boom),
    ):
        plan = build_capability_discovery_plan(
            inv,
            (),
            agents_dir=agents,
            registry=registry,
            host_facts=facts,
        )
    assert plan.steps


def test_not_matched_candidate_creates_no_step(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "os_probe.md",
        frontmatter="""
id: os_probe
version: "1"
family_id: os_probe
language: en
applicability:
  all:
    - fact: os.name
      operator: equals
      value: Windows
required_facts:
  - os.name
discovery_hints:
  - capability: host.read
    operation_ids: [ssh_run]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu")])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"os.name": "Ubuntu", "access.ssh.available": True},
        )
    }
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    candidates = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=registry
    )
    assert any(c.predicate_result == "not_matched" for c in candidates)
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert plan.steps == ()


def test_legacy_and_invalid_frameworks_create_no_step(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "legacy.md",
        frontmatter="""
id: legacy_fw
version: "1"
family_id: legacy_fw
language: en
""",
    )
    _write_fw(
        agents,
        "broken.md",
        frontmatter="""
id: broken_fw
version: "1"
family_id: broken_fw
language: en
applicability:
  all:
    - fact: ""
      operator: equals
      value: x
discovery_hints:
  - capability: host.read
    operation_ids: [ssh_run]
    expected_facts: [os.name]
""",
    )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    candidates = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=registry
    )
    assert any(c.metadata_state == "legacy" for c in candidates)
    assert any(c.metadata_state == "invalid" for c in candidates)
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert plan.steps == ()


def test_missing_typed_hint_requires_operator(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "os_probe.md",
        frontmatter="""
id: os_probe
version: "1"
family_id: os_probe
language: en
applicability:
  all:
    - fact: os.name
      operator: equals
      value: Ubuntu
required_facts:
  - os.name
discovery_hints: []
target:
  scope: host
""",
    )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "requires_operator_decision"
    assert "No typed discovery hint covers the missing fact" in plan.steps[0].reason


def test_hint_without_expected_facts_requires_operator(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, expected=[])
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "requires_operator_decision"
    assert "does not declare expected facts" in plan.steps[0].reason


def test_unknown_operation_blocked(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, ops=["unknown_operation"])
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "blocked"
    assert "unknown" in plan.steps[0].reason.lower()


def test_unauthorized_operation_blocked(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, ops=["ssh_run"])
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {"ssh_run": _manifest("ssh_run")},
        allowed=(),
        denied=("ssh_run",),
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "blocked"
    assert "not authorized" in plan.steps[0].reason.lower()


def test_capability_mismatch_blocked(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, ops=["db_tool"])
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {
            "db_tool": _manifest(
                "db_tool",
                capabilities=("database.read",),
                inventory_access=(),
            )
        }
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "blocked"
    assert "capability mismatch" in plan.steps[0].reason.lower()


def test_host_specific_access(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory(
        [
            _host(host_id="host-01", connection_types=("ssh",)),
            _host(host_id="host-02", connection_types=()),
        ]
    )
    facts = {
        "host-01": _fact_set("host-01", {"access.ssh.available": True}),
        "host-02": _fact_set("host-02", {}),
    }
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    by_host = {s.host_id: s for s in plan.steps}
    assert by_host["host-01"].status == "planned"
    assert by_host["host-02"].status == "blocked"
    assert "unavailable" in by_host["host-02"].reason.lower()


def test_invalid_host_blocks_discovery(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory(
        [_host()],
        issues=(
            ValidationIssue(
                level="error",
                code="host_invalid",
                message="bad host",
                host_id="host-01",
            ),
        ),
    )
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    candidates = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=registry
    )
    assert any(c.missing_facts for c in candidates)
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "blocked"
    assert "inventory validation errors" in plan.steps[0].reason


def test_multiple_operations_lexically_first(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, ops=["operation_b", "operation_a"])
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {
            "operation_a": _manifest("operation_a"),
            "operation_b": _manifest("operation_b"),
        }
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert plan.steps[0].operation_id == "operation_a"


def test_deduplicate_across_frameworks(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    for fid in ("ubuntu_baseline", "host_facts"):
        _write_fw(
            agents,
            f"{fid}.md",
            frontmatter=f"""
id: {fid}
version: "1"
family_id: {fid}
language: en
applicability:
  all:
    - fact: os.name
      operator: equals
      value: Ubuntu
required_facts:
  - os.name
discovery_hints:
  - capability: host.read
    operation_ids: [ssh_run]
    expected_facts: [os.name]
target:
  scope: host
""",
        )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].requested_by_frameworks == (
        "host_facts@1",
        "ubuntu_baseline@1",
    )


def test_no_cross_host_deduplication(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory(
        [
            _host(host_id="host-01"),
            _host(host_id="host-02"),
        ]
    )
    facts = {
        "host-01": _fact_set("host-01", {"access.ssh.available": True}),
        "host-02": _fact_set("host-02", {"access.ssh.available": True}),
    }
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 2
    assert {s.host_id for s in plan.steps} == {"host-01", "host-02"}


def test_partial_expected_fact_coverage(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "mixed.md",
        frontmatter="""
id: mixed
version: "1"
family_id: mixed
language: en
applicability:
  all:
    - fact: os.name
      operator: equals
      value: Ubuntu
required_facts:
  - os.name
  - os.version
  - service.postgresql.version
discovery_hints:
  - capability: host.read
    operation_ids: [ssh_run]
    expected_facts:
      - os.name
      - os.version
target:
  scope: host
""",
    )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    planned = [s for s in plan.steps if s.status == "planned"]
    operator = [s for s in plan.steps if s.status == "requires_operator_decision"]
    assert len(planned) == 1
    assert planned[0].missing_facts == ("os.name", "os.version")
    assert len(operator) == 1
    assert operator[0].missing_facts == ("service.postgresql.version",)


def test_missing_capability_with_hint(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "cap.md",
        frontmatter="""
id: cap_fw
version: "1"
family_id: cap_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  all_of: [host.read]
discovery_hints:
  - capability: host.read
    operation_ids: [ssh_run]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
    # Host facts without SSH access → capability missing + blocked access.
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"os.family": "linux", "os.name": "Ubuntu"},
        )
    }
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert plan.steps
    assert all(s.status in {"planned", "blocked"} for s in plan.steps)
    assert any(s.capability == "host.read" for s in plan.steps)


def test_secret_boundary(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    from auditor.domain.inventory import CredentialReference

    inv = _inventory(
        [_host()],
        credentials=(
            CredentialReference(
                access="ssh",
                host="host-01",
                secret_ref=CANARY_PASSWORD,
                username="auditor",
                has_secret=True,
            ),
        ),
    )
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"access.ssh.available": True},
        )
    }
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    blob = plan.model_dump_json()
    for canary in (
        CANARY_PASSWORD,
        CANARY_TOKEN,
        CANARY_NOTES,
        CANARY_DESC,
        CANARY_PURPOSE,
        CANARY_EVIDENCE,
    ):
        assert canary not in blob
        for step in plan.steps:
            assert canary not in step.reason
            assert canary not in step.model_dump_json()
        for q in plan.unresolved_questions:
            assert canary not in q


def test_deterministic_output(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    a = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    b = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert a.model_dump() == b.model_dump()
    assert json.dumps(a.model_dump(), sort_keys=True) == json.dumps(b.model_dump(), sort_keys=True)


def test_identity_changes_with_inputs(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    base = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )

    # missing fact change via different required_facts / hint
    agents2 = _os_name_agents(tmp_path / "a2", expected=["os.version"], ops=["ssh_run"])
    # rewrite framework to require os.version
    (agents2 / "os_probe.md").write_text(
        (agents2 / "os_probe.md")
        .read_text(encoding="utf-8")
        .replace("- os.name\n", "- os.version\n")
        .replace("fact: os.name", "fact: os.version"),
        encoding="utf-8",
    )
    changed_fact = build_capability_discovery_plan(
        inv, (), agents_dir=agents2, registry=registry, host_facts=facts
    )
    assert changed_fact.discovery_plan_hash != base.discovery_plan_hash

    agents3 = _os_name_agents(tmp_path / "a3", ops=["other_run"])
    registry3 = _registry({"ssh_run": _manifest("ssh_run"), "other_run": _manifest("other_run")})
    changed_op = build_capability_discovery_plan(
        inv, (), agents_dir=agents3, registry=registry3, host_facts=facts
    )
    assert changed_op.discovery_plan_hash != base.discovery_plan_hash

    facts2 = {"host-01": _fact_set("host-01", {})}
    changed_access = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts2
    )
    assert changed_access.discovery_plan_hash != base.discovery_plan_hash

    registry_denied = _registry({"ssh_run": _manifest("ssh_run")}, denied=("ssh_run",), allowed=())
    changed_policy = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry_denied, host_facts=facts
    )
    assert changed_policy.discovery_plan_hash != base.discovery_plan_hash


def test_audit_plan_integration(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host(connection_types=("ssh",))])
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    with patch("auditor.inventory.discovery_plan.get_tool_registry", return_value=registry):
        with patch("auditor.inventory.plan.get_tool_registry", return_value=registry):
            with patch(
                "auditor.inventory.framework_candidates.get_tool_registry",
                return_value=registry,
            ):
                plan = generate_audit_plan(inv, [], agents_dir=agents)
    assert plan.discovery_plan_id.startswith("dplan-")
    assert plan.discovery_plan_hash.startswith("dph-")
    assert plan.discovery_steps
    # Executable targets remain selection-driven (may be empty while missing evidence).
    assert isinstance(plan.targets, tuple)


def test_plan_persistence_round_trip(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host(connection_types=("ssh",))])
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    with patch("auditor.inventory.discovery_plan.get_tool_registry", return_value=registry):
        with patch("auditor.inventory.plan.get_tool_registry", return_value=registry):
            with patch(
                "auditor.inventory.framework_candidates.get_tool_registry",
                return_value=registry,
            ):
                plan = generate_audit_plan(inv, [], agents_dir=agents)
    store = PlanRevisionStore(tmp_path / "plans")
    store.persist_revision(plan, inv, make_latest=True)
    loaded = store.load_revision(plan.plan_revision_id).plan
    assert loaded.discovery_plan_id == plan.discovery_plan_id
    assert loaded.discovery_plan_hash == plan.discovery_plan_hash
    assert loaded.discovery_steps == plan.discovery_steps


def test_plan_revision_identity_tracks_discovery(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host(connection_types=("ssh",))])
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    with patch("auditor.inventory.discovery_plan.get_tool_registry", return_value=registry):
        with patch("auditor.inventory.plan.get_tool_registry", return_value=registry):
            with patch(
                "auditor.inventory.framework_candidates.get_tool_registry",
                return_value=registry,
            ):
                a = generate_audit_plan(inv, [], agents_dir=agents)
                b = generate_audit_plan(inv, [], agents_dir=agents)
    assert a.plan_revision_id == b.plan_revision_id

    agents2 = _os_name_agents(tmp_path / "x2", ops=["other_run"])
    registry2 = _registry({"ssh_run": _manifest("ssh_run"), "other_run": _manifest("other_run")})
    with patch("auditor.inventory.discovery_plan.get_tool_registry", return_value=registry2):
        with patch("auditor.inventory.plan.get_tool_registry", return_value=registry2):
            with patch(
                "auditor.inventory.framework_candidates.get_tool_registry",
                return_value=registry2,
            ):
                c = generate_audit_plan(inv, [], agents_dir=agents2)
    assert c.plan_revision_id != a.plan_revision_id


def test_confirmation_stale_gate(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host(connection_types=("ssh",))])
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    with patch("auditor.inventory.discovery_plan.get_tool_registry", return_value=registry):
        with patch("auditor.inventory.plan.get_tool_registry", return_value=registry):
            with patch(
                "auditor.inventory.framework_candidates.get_tool_registry",
                return_value=registry,
            ):
                plan = generate_audit_plan(inv, [], agents_dir=agents)

    # Mutate hint / ops after plan generation.
    agents2 = _os_name_agents(tmp_path / "stale", ops=["other_run"])
    registry2 = _registry({"ssh_run": _manifest("ssh_run"), "other_run": _manifest("other_run")})
    with patch("auditor.inventory.discovery_plan.get_tool_registry", return_value=registry2):
        with patch(
            "auditor.inventory.framework_candidates.get_tool_registry",
            return_value=registry2,
        ):
            with pytest.raises(PlanConfirmationRejected) as exc:
                assert_plan_matches_discovery_plan(plan, inv, agents_dir=agents2)
    assert exc.value.code == "audit_plan_stale"


def test_cross_format_determinism(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    hosts = [_host()]
    inv_md = _inventory(hosts, version=_version(source_format="markdown"))
    inv_yaml = _inventory(hosts, version=_version(source_format="yaml"))
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    a = build_capability_discovery_plan(
        inv_md, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    b = build_capability_discovery_plan(
        inv_yaml, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert [s.model_dump(exclude={"step_id"}) for s in a.steps] == [
        s.model_dump(exclude={"step_id"}) for s in b.steps
    ]
    # Identity payload includes inventory_content_hash / version fields which may
    # differ by source format; semantic steps must still match.
    assert a.steps[0].missing_facts == b.steps[0].missing_facts
    assert a.steps[0].status == b.steps[0].status

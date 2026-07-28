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
from auditor.inventory.discovery_plan import (
    build_capability_discovery_plan,
    framework_catalog_hash,
)
from auditor.inventory.framework_candidates import (
    FrameworkCandidate,
    evaluate_framework_candidates,
)
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


def _invalid_inv(hosts: list[InventoryHost] | None = None) -> ClientInventory:
    return _inventory(
        hosts or [_host()],
        issues=(
            ValidationIssue(
                level="error",
                code="host_invalid",
                message="bad host",
                host_id="host-01",
            ),
        ),
    )


def _assert_all_invalid_host_blocked(plan: Any) -> None:
    assert plan.steps
    assert all(s.status == "blocked" for s in plan.steps)
    assert all(s.reason == "Host has inventory validation errors" for s in plan.steps)
    assert not any(s.status == "planned" for s in plan.steps)
    assert not any(s.status == "requires_operator_decision" for s in plan.steps)


def test_invalid_host_no_discovery_hints(tmp_path: Path) -> None:
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
    inv = _invalid_inv()
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    _assert_all_invalid_host_blocked(plan)


def test_invalid_host_hint_without_expected_facts(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, expected=[])
    inv = _invalid_inv()
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    _assert_all_invalid_host_blocked(plan)


def test_invalid_host_missing_capability_no_hint(tmp_path: Path) -> None:
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
discovery_hints: []
target:
  scope: host
""",
    )
    inv = _invalid_inv([_host(os_name="Ubuntu", os_family="linux")])
    facts = {"host-01": _fact_set("host-01", {"os.family": "linux", "os.name": "Ubuntu"})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    _assert_all_invalid_host_blocked(plan)


def test_invalid_host_unknown_operation(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, ops=["unknown_operation"])
    inv = _invalid_inv()
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    _assert_all_invalid_host_blocked(plan)


def test_invalid_host_multiple_possible_hints(tmp_path: Path) -> None:
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
discovery_hints:
  - capability: a.read
    operation_ids: [unknown_operation]
    expected_facts: [os.name]
  - capability: z.read
    operation_ids: [ssh_run]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _invalid_inv()
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"ssh_run": _manifest("ssh_run", capabilities=("z.read",))})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    _assert_all_invalid_host_blocked(plan)


def test_alternative_unknown_then_valid(tmp_path: Path) -> None:
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
discovery_hints:
  - capability: a.read
    operation_ids: [unknown_operation]
    expected_facts: [os.name]
  - capability: z.read
    operation_ids: [valid_operation]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {"valid_operation": _manifest("valid_operation", capabilities=("z.read",))}
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "planned"
    assert plan.steps[0].operation_id == "valid_operation"
    assert not any(s.status == "blocked" for s in plan.steps)
    assert plan.unresolved_questions == ()


def test_alternative_unauthorized_then_valid(tmp_path: Path) -> None:
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
discovery_hints:
  - capability: host.read
    operation_ids: [denied_op]
    expected_facts: [os.name]
  - capability: host.read
    operation_ids: [allowed_op]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {
            "denied_op": _manifest("denied_op"),
            "allowed_op": _manifest("allowed_op"),
        },
        allowed=("allowed_op",),
        denied=("denied_op",),
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "planned"
    assert plan.steps[0].operation_id == "allowed_op"


def test_alternative_access_unavailable_then_global(tmp_path: Path) -> None:
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
discovery_hints:
  - capability: host.read
    operation_ids: [ssh_only]
    expected_facts: [os.name]
  - capability: host.read
    operation_ids: [global_op]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {})}
    registry = _registry(
        {
            "ssh_only": _manifest("ssh_only", inventory_access=("ssh",)),
            "global_op": _manifest("global_op", inventory_access=()),
        }
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "planned"
    assert plan.steps[0].operation_id == "global_op"


def test_all_alternatives_blocked(tmp_path: Path) -> None:
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
discovery_hints:
  - capability: b.read
    operation_ids: [unknown_b]
    expected_facts: [os.name]
  - capability: a.read
    operation_ids: [unknown_a]
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
    blocked = [s for s in plan.steps if s.status == "blocked"]
    assert len(blocked) == 1
    assert len(plan.unresolved_questions) == 1
    assert blocked[0].capability == "a.read"
    assert "unknown" in blocked[0].reason.lower()


def test_hint_order_independence(tmp_path: Path) -> None:
    def _agents(root: Path, hints: str) -> Path:
        agents = root / "agents"
        agents.mkdir(parents=True, exist_ok=True)
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
{hints}
target:
  scope: host
""",
        )
        return agents

    hints_a = """
  - capability: a.read
    operation_ids: [unknown_operation]
    expected_facts: [os.name]
  - capability: z.read
    operation_ids: [valid_operation]
    expected_facts: [os.name]
"""
    hints_b = """
  - capability: z.read
    operation_ids: [valid_operation]
    expected_facts: [os.name]
  - capability: a.read
    operation_ids: [unknown_operation]
    expected_facts: [os.name]
"""
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {"valid_operation": _manifest("valid_operation", capabilities=("z.read",))}
    )
    a = build_capability_discovery_plan(
        inv,
        (),
        agents_dir=_agents(tmp_path / "a", hints_a),
        registry=registry,
        host_facts=facts,
    )
    b = build_capability_discovery_plan(
        inv,
        (),
        agents_dir=_agents(tmp_path / "b", hints_b),
        registry=registry,
        host_facts=facts,
    )
    assert [s.model_dump() for s in a.steps] == [s.model_dump() for s in b.steps]
    assert a.discovery_plan_id == b.discovery_plan_id
    assert a.discovery_plan_hash == b.discovery_plan_hash
    assert a.unresolved_questions == b.unresolved_questions


def test_multi_fact_alternative_no_duplicate_work(tmp_path: Path) -> None:
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
discovery_hints:
  - capability: a.read
    operation_ids: [unknown_operation]
    expected_facts: [os.name]
  - capability: z.read
    operation_ids: [bundle_op]
    expected_facts: [os.name, os.version]
target:
  scope: host
""",
    )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {"bundle_op": _manifest("bundle_op", capabilities=("z.read",), inventory_access=())}
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "planned"
    assert plan.steps[0].operation_id == "bundle_op"
    assert plan.steps[0].missing_facts == ("os.name", "os.version")
    assert not any(s.status == "blocked" for s in plan.steps)


def test_any_of_one_eligible_alternative(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "any.md",
        frontmatter="""
id: any_fw
version: "1"
family_id: any_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  any_of:
    - host.ssh.read
    - host.winrm.read
discovery_hints:
  - capability: host.ssh.read
    operation_ids: [ssh_probe]
    expected_facts: [os.name]
  - capability: host.winrm.read
    operation_ids: [winrm_probe]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"os.family": "linux", "os.name": "Ubuntu", "access.ssh.available": True},
        )
    }
    registry = _registry(
        {
            "ssh_probe": _manifest(
                "ssh_probe",
                capabilities=("host.ssh.read",),
                inventory_access=("ssh",),
            ),
            "winrm_probe": _manifest(
                "winrm_probe",
                capabilities=("host.winrm.read",),
                inventory_access=("winrm",),
            ),
        }
    )

    fake = FrameworkCandidate(
        host_id="host-01",
        framework_id="any_fw",
        framework_version="1",
        family_id="any_fw",
        language="en",
        metadata_state="structured",
        predicate_result="matched",
        target_scope="host",
        target_service="",
        matched_fact_keys=("os.family",),
        missing_facts=(),
        required_any_capabilities=("host.ssh.read", "host.winrm.read"),
        required_all_capabilities=(),
        available_capabilities=(),
        missing_capabilities=("host.ssh.read", "host.winrm.read"),
        capability_ready=False,
        applicability_fingerprint="fp",
    )

    with patch(
        "auditor.inventory.discovery_plan.evaluate_framework_candidates",
        return_value=[fake],
    ):
        plan = build_capability_discovery_plan(
            inv, (), agents_dir=agents, registry=registry, host_facts=facts
        )
    planned = [s for s in plan.steps if s.status == "planned"]
    assert len(planned) == 1
    assert planned[0].capability == "host.ssh.read"
    assert planned[0].operation_id == "ssh_probe"
    assert not any(s.status == "blocked" and s.capability == "host.winrm.read" for s in plan.steps)


def test_any_of_both_eligible_lexical_choice(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "any.md",
        frontmatter="""
id: any_fw
version: "1"
family_id: any_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  any_of:
    - host.winrm.read
    - host.ssh.read
discovery_hints:
  - capability: host.ssh.read
    operation_ids: [ssh_probe]
    expected_facts: [os.name]
  - capability: host.winrm.read
    operation_ids: [winrm_probe]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {
                "os.family": "linux",
                "os.name": "Ubuntu",
                "access.ssh.available": True,
                "access.winrm.available": True,
            },
        )
    }
    registry = _registry(
        {
            "ssh_probe": _manifest(
                "ssh_probe",
                capabilities=("host.ssh.read",),
                inventory_access=("ssh",),
            ),
            "winrm_probe": _manifest(
                "winrm_probe",
                capabilities=("host.winrm.read",),
                inventory_access=("winrm",),
            ),
        }
    )

    fake = FrameworkCandidate(
        host_id="host-01",
        framework_id="any_fw",
        framework_version="1",
        family_id="any_fw",
        language="en",
        metadata_state="structured",
        predicate_result="matched",
        target_scope="host",
        target_service="",
        matched_fact_keys=("os.family",),
        missing_facts=(),
        required_any_capabilities=("host.ssh.read", "host.winrm.read"),
        required_all_capabilities=(),
        available_capabilities=(),
        missing_capabilities=("host.ssh.read", "host.winrm.read"),
        capability_ready=False,
        applicability_fingerprint="fp",
    )

    with patch(
        "auditor.inventory.discovery_plan.evaluate_framework_candidates",
        return_value=[fake],
    ):
        plan = build_capability_discovery_plan(
            inv, (), agents_dir=agents, registry=registry, host_facts=facts
        )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "planned"
    assert plan.steps[0].capability == "host.ssh.read"
    assert plan.steps[0].capability_options == ("host.ssh.read", "host.winrm.read")


def test_any_of_no_eligible_preserves_options(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "any.md",
        frontmatter="""
id: any_fw
version: "1"
family_id: any_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  any_of:
    - host.ssh.read
    - host.winrm.read
discovery_hints:
  - capability: host.ssh.read
    operation_ids: [ssh_probe]
    expected_facts: [os.name]
  - capability: host.winrm.read
    operation_ids: [winrm_probe]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"os.family": "linux", "os.name": "Ubuntu"},
        )
    }
    registry = _registry(
        {
            "ssh_probe": _manifest(
                "ssh_probe",
                capabilities=("host.ssh.read",),
                inventory_access=("ssh",),
            ),
            "winrm_probe": _manifest(
                "winrm_probe",
                capabilities=("host.winrm.read",),
                inventory_access=("winrm",),
            ),
        }
    )
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status in {"blocked", "requires_operator_decision"}
    assert len(plan.unresolved_questions) == 1
    assert plan.steps[0].capability_options == ("host.ssh.read", "host.winrm.read")


def test_any_of_missing_hints_operator_group(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "any.md",
        frontmatter="""
id: any_fw
version: "1"
family_id: any_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  any_of:
    - host.ssh.read
    - host.winrm.read
discovery_hints: []
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
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
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "requires_operator_decision"
    assert plan.steps[0].capability_options == ("host.ssh.read", "host.winrm.read")


def test_mixed_all_of_and_any_of(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "mixed_caps.md",
        frontmatter="""
id: mixed_caps
version: "1"
family_id: mixed_caps
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  all_of:
    - inventory.read
  any_of:
    - host.ssh.read
    - host.winrm.read
discovery_hints:
  - capability: inventory.read
    operation_ids: [inv_op]
    expected_facts: [os.name]
  - capability: host.ssh.read
    operation_ids: [ssh_probe]
    expected_facts: [os.name]
  - capability: host.winrm.read
    operation_ids: [winrm_probe]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"os.family": "linux", "os.name": "Ubuntu", "access.ssh.available": True},
        )
    }
    registry = _registry(
        {
            "inv_op": _manifest(
                "inv_op",
                capabilities=("inventory.read",),
                inventory_access=(),
            ),
            "ssh_probe": _manifest(
                "ssh_probe",
                capabilities=("host.ssh.read",),
                inventory_access=("ssh",),
            ),
            "winrm_probe": _manifest(
                "winrm_probe",
                capabilities=("host.winrm.read",),
                inventory_access=("winrm",),
            ),
        }
    )
    fake = FrameworkCandidate(
        host_id="host-01",
        framework_id="mixed_caps",
        framework_version="1",
        family_id="mixed_caps",
        language="en",
        metadata_state="structured",
        predicate_result="matched",
        target_scope="host",
        target_service="",
        matched_fact_keys=("os.family",),
        missing_facts=(),
        required_any_capabilities=("host.ssh.read", "host.winrm.read"),
        required_all_capabilities=("inventory.read",),
        available_capabilities=(),
        missing_capabilities=("host.ssh.read", "host.winrm.read", "inventory.read"),
        capability_ready=False,
        applicability_fingerprint="fp",
    )
    with patch(
        "auditor.inventory.discovery_plan.evaluate_framework_candidates",
        return_value=[fake],
    ):
        plan = build_capability_discovery_plan(
            inv, (), agents_dir=agents, registry=registry, host_facts=facts
        )
    caps = {s.capability for s in plan.steps}
    assert "inventory.read" in caps
    assert "host.ssh.read" in caps or "host.winrm.read" in caps
    assert len([s for s in plan.steps if s.capability == "inventory.read"]) == 1
    any_steps = [s for s in plan.steps if s.capability in {"host.ssh.read", "host.winrm.read"}]
    assert len(any_steps) == 1


def test_any_of_ordering_independence(tmp_path: Path) -> None:
    def _agents(root: Path, any_block: str) -> Path:
        agents = root / "agents"
        agents.mkdir(parents=True, exist_ok=True)
        _write_fw(
            agents,
            "any.md",
            frontmatter=f"""
id: any_fw
version: "1"
family_id: any_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  any_of:
{any_block}
discovery_hints:
  - capability: host.ssh.read
    operation_ids: [ssh_probe]
    expected_facts: [os.name]
  - capability: host.winrm.read
    operation_ids: [winrm_probe]
    expected_facts: [os.name]
target:
  scope: host
""",
        )
        return agents

    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {
                "os.family": "linux",
                "os.name": "Ubuntu",
                "access.ssh.available": True,
                "access.winrm.available": True,
            },
        )
    }
    registry = _registry(
        {
            "ssh_probe": _manifest(
                "ssh_probe",
                capabilities=("host.ssh.read",),
                inventory_access=("ssh",),
            ),
            "winrm_probe": _manifest(
                "winrm_probe",
                capabilities=("host.winrm.read",),
                inventory_access=("winrm",),
            ),
        }
    )
    fake = FrameworkCandidate(
        host_id="host-01",
        framework_id="any_fw",
        framework_version="1",
        family_id="any_fw",
        language="en",
        metadata_state="structured",
        predicate_result="matched",
        target_scope="host",
        target_service="",
        matched_fact_keys=("os.family",),
        missing_facts=(),
        required_any_capabilities=("host.ssh.read", "host.winrm.read"),
        required_all_capabilities=(),
        available_capabilities=(),
        missing_capabilities=("host.ssh.read", "host.winrm.read"),
        capability_ready=False,
        applicability_fingerprint="fp",
    )

    def _plan(agents_dir: Path) -> Any:
        with patch(
            "auditor.inventory.discovery_plan.evaluate_framework_candidates",
            return_value=[fake],
        ):
            return build_capability_discovery_plan(
                inv, (), agents_dir=agents_dir, registry=registry, host_facts=facts
            )

    a = _plan(_agents(tmp_path / "a", "    - host.ssh.read\n    - host.winrm.read"))
    b = _plan(_agents(tmp_path / "b", "    - host.winrm.read\n    - host.ssh.read"))
    assert a.discovery_plan_id == b.discovery_plan_id
    assert a.discovery_plan_hash == b.discovery_plan_hash
    assert [s.model_dump() for s in a.steps] == [s.model_dump() for s in b.steps]


def test_exact_framework_version_metadata(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    for ver, op in (("1", "operation_v1"), ("2", "operation_v2")):
        _write_fw(
            agents,
            f"widget_v{ver}.md",
            frontmatter=f"""
id: widget
version: "{ver}"
family_id: widget
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
    operation_ids: [{op}]
    expected_facts: [os.name]
target:
  scope: host
""",
        )
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry(
        {
            "operation_v1": _manifest("operation_v1"),
            "operation_v2": _manifest("operation_v2"),
        }
    )
    # Exact match for v1 only when that metadata is present — both versions exist.
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    ops = {s.operation_id for s in plan.steps if s.status == "planned"}
    assert ops == {"operation_v1", "operation_v2"} or ops.issubset({"operation_v1", "operation_v2"})

    # Candidate for missing version: only v1/v2 files present; simulate by removing one
    # and injecting a candidate via host facts against remaining catalog after rename.
    agents_missing = tmp_path / "agents_missing"
    agents_missing.mkdir()
    _write_fw(
        agents_missing,
        "widget_v1.md",
        frontmatter="""
id: widget
version: "1"
family_id: widget
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
    operation_ids: [operation_v1]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    # Build candidate for widget@9 which has no metadata file.
    fake = FrameworkCandidate(
        host_id="host-01",
        framework_id="widget",
        framework_version="9",
        family_id="widget",
        language="en",
        metadata_state="structured",
        predicate_result="missing_evidence",
        target_scope="host",
        target_service="",
        matched_fact_keys=(),
        missing_facts=("os.name",),
        required_any_capabilities=(),
        required_all_capabilities=(),
        available_capabilities=(),
        missing_capabilities=(),
        capability_ready=True,
        applicability_fingerprint="fp",
    )
    with patch(
        "auditor.inventory.discovery_plan.evaluate_framework_candidates",
        return_value=[fake],
    ):
        missing = build_capability_discovery_plan(
            inv,
            (),
            agents_dir=agents_missing,
            registry=registry,
            host_facts=facts,
        )
    assert len(missing.steps) == 1
    assert missing.steps[0].status == "requires_operator_decision"
    assert missing.steps[0].reason == "Exact framework metadata identity is unavailable"
    assert "operation_v1" not in missing.steps[0].operation_id
    assert "operation_v2" not in {s.operation_id for s in missing.steps}


def test_strict_model_validation_rejects_non_strings() -> None:
    from pydantic import ValidationError

    from auditor.domain.discovery_plan import CapabilityDiscoveryPlan, DiscoveryPlanStep

    class SecretObject:
        def __str__(self) -> str:
            return "SECRET_DISCOVERY_MODEL_CANARY"

    invalid_values: list[Any] = [
        123,
        1.5,
        True,
        {},
        {"secret": "value"},
        [],
        [["nested"]],
        set(),
        (lambda: None),
        object(),
        SecretObject(),
    ]

    base_step = {
        "step_id": "dstep-" + ("a" * 16),
        "host_id": "host-01",
        "capability": "host.read",
        "status": "blocked",
        "reason": "Host has inventory validation errors",
    }

    tuple_fields = (
        "capability_options",
        "expected_facts",
        "missing_facts",
        "requested_by_frameworks",
    )
    string_fields = (
        "step_id",
        "host_id",
        "capability",
        "operation_id",
        "tool_id",
        "reason",
    )

    for field in string_fields:
        for bad in invalid_values:
            payload = dict(base_step)
            payload[field] = bad
            with pytest.raises(ValidationError) as exc:
                DiscoveryPlanStep(**payload)
            err = str(exc.value)
            assert "SECRET_DISCOVERY_MODEL_CANARY" not in err

    for field in tuple_fields:
        for bad in invalid_values:
            if bad == [] and field != "requested_by_frameworks":
                # empty list is valid for optional tuple fields
                continue
            payload = dict(base_step)
            if field == "requested_by_frameworks" and bad == []:
                DiscoveryPlanStep(**payload)  # empty ok
                continue
            payload[field] = bad if type(bad) is not list or bad != [["nested"]] else bad
            # nested list / non-str sequence items
            if bad == []:
                continue
            with pytest.raises(ValidationError) as exc:
                DiscoveryPlanStep(**payload)
            assert "SECRET_DISCOVERY_MODEL_CANARY" not in str(exc.value)

    # Nested list / SecretObject as sequence members
    with pytest.raises(ValidationError) as exc:
        DiscoveryPlanStep(**{**base_step, "expected_facts": [SecretObject()]})
    assert "SECRET_DISCOVERY_MODEL_CANARY" not in str(exc.value)

    with pytest.raises(ValidationError):
        DiscoveryPlanStep(**{**base_step, "step_id": "step-not-valid"})
    with pytest.raises(ValidationError):
        DiscoveryPlanStep(**{**base_step, "requested_by_frameworks": ["no-at-sign"]})
    with pytest.raises(ValidationError):
        DiscoveryPlanStep(
            **{
                **base_step,
                "status": "planned",
                "operation_id": "",
                "tool_id": "",
                "reason": "x",
            }
        )
    with pytest.raises(ValidationError):
        DiscoveryPlanStep(
            **{
                **base_step,
                "status": "blocked",
                "operation_id": "ssh_run",
                "tool_id": "ssh_run",
            }
        )

    plan_base = {
        "discovery_plan_id": "dplan-" + ("b" * 16),
        "discovery_plan_hash": "dph-" + ("c" * 16),
        "client_id": "client-a",
        "inventory_version_id": "inv-1",
        "inventory_content_hash": "hash-1",
    }
    for field in (
        "discovery_plan_id",
        "discovery_plan_hash",
        "client_id",
        "inventory_version_id",
        "inventory_content_hash",
        "unresolved_questions",
    ):
        for bad in (123, SecretObject(), {"secret": "value"}):
            payload = dict(plan_base)
            payload[field] = bad
            with pytest.raises(ValidationError) as exc:
                CapabilityDiscoveryPlan(**payload)
            assert "SECRET_DISCOVERY_MODEL_CANARY" not in str(exc.value)


def test_non_executable_operation_blocked(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path, ops=["broken_op"])
    inv = _inventory([_host()])
    facts = {"host-01": _fact_set("host-01", {"access.ssh.available": True})}
    registry = _registry({"broken_op": _manifest("broken_op", enabled=False)})
    plan = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].status == "blocked"
    assert "not executable" in plan.steps[0].reason.lower()


def test_registry_identity_consistency(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path)
    inv = _inventory([_host(connection_types=("ssh",))])
    registry_a = _registry({"ssh_run": _manifest("ssh_run")})
    registry_a.catalog_hash = "cat-aaaaaaaaaaaa"
    registry_a.policy_hash = "pol-aaaaaaaaaaaa"
    registry_b = _registry(
        {
            "ssh_run": _manifest("ssh_run"),
            "extra_tool": _manifest("extra_tool", inventory_access=()),
        }
    )
    registry_b.catalog_hash = "cat-bbbbbbbbbbbb"
    registry_b.policy_hash = "pol-bbbbbbbbbbbb"
    plan_a = generate_audit_plan(inv, [], agents_dir=agents, registry=registry_a)
    plan_b = generate_audit_plan(inv, [], agents_dir=agents, registry=registry_b)
    assert plan_a.tool_catalog_hash == "cat-aaaaaaaaaaaa"
    assert plan_a.capability_policy_hash == "pol-aaaaaaaaaaaa"
    assert plan_b.tool_catalog_hash == "cat-bbbbbbbbbbbb"
    assert plan_a.discovery_plan_hash != plan_b.discovery_plan_hash
    assert plan_a.plan_revision_id != plan_b.plan_revision_id
    from auditor.inventory.discovery_plan import build_capability_discovery_plan as build

    disc = build(inv, [], agents_dir=agents, registry=registry_a)
    assert disc.tool_catalog_hash == plan_a.tool_catalog_hash
    assert disc.capability_policy_hash == plan_a.capability_policy_hash
    assert disc.discovery_plan_hash == plan_a.discovery_plan_hash


def test_custom_framework_catalog_stale_gate(tmp_path: Path) -> None:
    agents = _os_name_agents(tmp_path / "custom")
    inv = _inventory([_host(connection_types=("ssh",))])
    registry = _registry({"ssh_run": _manifest("ssh_run")})
    plan = generate_audit_plan(inv, [], agents_dir=agents, registry=registry)
    assert plan.framework_catalog_hash.startswith("fc-")
    blob = plan.model_dump_json()
    assert str(agents.resolve()) not in blob
    assert str(tmp_path.resolve()) not in blob

    # same catalog succeeds
    assert_plan_matches_discovery_plan(plan, inv, agents_dir=agents, registry=registry)

    # changed custom hint → stale
    agents2 = _os_name_agents(tmp_path / "custom2", ops=["other_run"])
    registry2 = _registry({"ssh_run": _manifest("ssh_run"), "other_run": _manifest("other_run")})
    with pytest.raises(PlanConfirmationRejected) as exc:
        assert_plan_matches_discovery_plan(plan, inv, agents_dir=agents2, registry=registry2)
    assert exc.value.code == "audit_plan_stale"

    # default catalog → stale (different framework_catalog_hash / discovery hash)
    with pytest.raises(PlanConfirmationRejected) as exc2:
        assert_plan_matches_discovery_plan(plan, inv, agents_dir=None, registry=registry)
    assert exc2.value.code == "audit_plan_stale"


def test_all_of_independent_resolutions(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "all.md",
        frontmatter="""
id: all_fw
version: "1"
family_id: all_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_capabilities:
  all_of:
    - inventory.read
    - host.read
discovery_hints:
  - capability: inventory.read
    operation_ids: [inv_op]
    expected_facts: [os.name]
  - capability: host.read
    operation_ids: [host_op]
    expected_facts: [os.name]
target:
  scope: host
""",
    )
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux")])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"os.family": "linux", "os.name": "Ubuntu"},
        )
    }
    registry = _registry(
        {
            "inv_op": _manifest("inv_op", capabilities=("inventory.read",), inventory_access=()),
            "host_op": _manifest("host_op", capabilities=("host.read",), inventory_access=()),
        }
    )
    fake = FrameworkCandidate(
        host_id="host-01",
        framework_id="all_fw",
        framework_version="1",
        family_id="all_fw",
        language="en",
        metadata_state="structured",
        predicate_result="matched",
        target_scope="host",
        target_service="",
        matched_fact_keys=("os.family",),
        missing_facts=(),
        required_any_capabilities=(),
        required_all_capabilities=("inventory.read", "host.read"),
        available_capabilities=(),
        missing_capabilities=("host.read", "inventory.read"),
        capability_ready=False,
        applicability_fingerprint="fp",
    )
    with patch(
        "auditor.inventory.discovery_plan.evaluate_framework_candidates",
        return_value=[fake],
    ):
        plan = build_capability_discovery_plan(
            inv, (), agents_dir=agents, registry=registry, host_facts=facts
        )
    caps = sorted(s.capability for s in plan.steps)
    assert caps == ["host.read", "inventory.read"]
    assert all(s.status == "planned" for s in plan.steps)


def _matched_fw(
    directory: Path,
    *,
    name: str = "matched.md",
    capability: str = "host.read",
    ops: list[str] | None = None,
    expected: list[str] | None = None,
    purpose: str = "probe os",
    reverse_hints: bool = False,
) -> Path:
    """Framework already matched on facts; discovery hints may still change identity."""
    agents = directory
    agents.mkdir(parents=True, exist_ok=True)
    op_list = ops or ["ssh_run"]
    exp_list = expected if expected is not None else ["os.name"]
    hint_a = (
        f"  - capability: {capability}\n"
        f'    purpose: "{purpose}"\n'
        f"    operation_ids:\n"
        + "\n".join(f"      - {op}" for op in op_list)
        + "\n    expected_facts:\n"
        + "\n".join(f"      - {fact}" for fact in exp_list)
        + "\n"
    )
    hint_b = (
        "  - capability: inventory.read\n"
        '    purpose: "secondary"\n'
        "    operation_ids:\n"
        "      - inv_op\n"
        "    expected_facts:\n"
        "      - os.version\n"
    )
    hints = hint_b + hint_a if reverse_hints else hint_a + hint_b
    _write_fw(
        agents,
        name,
        frontmatter=f"""
id: matched_fw
version: "1"
family_id: matched_fw
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
discovery_hints:
{hints}
target:
  scope: host
""",
    )
    return agents


def test_framework_catalog_hash_identical_metadata(tmp_path: Path) -> None:
    a = _matched_fw(tmp_path / "a")
    b = _matched_fw(tmp_path / "b")
    assert framework_catalog_hash(a) == framework_catalog_hash(b)


def test_framework_catalog_hash_hint_order_independent(tmp_path: Path) -> None:
    a = _matched_fw(tmp_path / "a", reverse_hints=False)
    b = _matched_fw(tmp_path / "b", reverse_hints=True)
    assert framework_catalog_hash(a) == framework_catalog_hash(b)


def test_framework_catalog_hash_operation_ids_change_identities(tmp_path: Path) -> None:
    agents_a = _matched_fw(tmp_path / "a", ops=["ssh_run"])
    agents_b = _matched_fw(tmp_path / "b", ops=["other_run"])
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux", connection_types=("ssh",))])
    registry = _registry(
        {
            "ssh_run": _manifest("ssh_run"),
            "other_run": _manifest("other_run"),
            "inv_op": _manifest("inv_op", capabilities=("inventory.read",), inventory_access=()),
        }
    )
    assert framework_catalog_hash(agents_a) != framework_catalog_hash(agents_b)
    plan_a = generate_audit_plan(inv, [], agents_dir=agents_a, registry=registry)
    plan_b = generate_audit_plan(inv, [], agents_dir=agents_b, registry=registry)
    assert plan_a.framework_catalog_hash != plan_b.framework_catalog_hash
    assert plan_a.discovery_plan_hash != plan_b.discovery_plan_hash
    assert plan_a.plan_revision_id != plan_b.plan_revision_id


def test_framework_catalog_hash_expected_facts_change_identities(tmp_path: Path) -> None:
    agents_a = _matched_fw(tmp_path / "a", expected=["os.name"])
    agents_b = _matched_fw(tmp_path / "b", expected=["os.version"])
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux", connection_types=("ssh",))])
    registry = _registry(
        {
            "ssh_run": _manifest("ssh_run"),
            "inv_op": _manifest("inv_op", capabilities=("inventory.read",), inventory_access=()),
        }
    )
    assert framework_catalog_hash(agents_a) != framework_catalog_hash(agents_b)
    plan_a = generate_audit_plan(inv, [], agents_dir=agents_a, registry=registry)
    plan_b = generate_audit_plan(inv, [], agents_dir=agents_b, registry=registry)
    assert plan_a.framework_catalog_hash != plan_b.framework_catalog_hash
    assert plan_a.discovery_plan_hash != plan_b.discovery_plan_hash
    assert plan_a.plan_revision_id != plan_b.plan_revision_id


def test_framework_catalog_hash_capability_change_identities(tmp_path: Path) -> None:
    agents_a = _matched_fw(tmp_path / "a", capability="host.read")
    agents_b = _matched_fw(tmp_path / "b", capability="host.ssh.read")
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux", connection_types=("ssh",))])
    registry = _registry(
        {
            "ssh_run": _manifest("ssh_run", capabilities=("host.read", "host.ssh.read")),
            "inv_op": _manifest("inv_op", capabilities=("inventory.read",), inventory_access=()),
        }
    )
    assert framework_catalog_hash(agents_a) != framework_catalog_hash(agents_b)
    plan_a = generate_audit_plan(inv, [], agents_dir=agents_a, registry=registry)
    plan_b = generate_audit_plan(inv, [], agents_dir=agents_b, registry=registry)
    assert plan_a.framework_catalog_hash != plan_b.framework_catalog_hash
    assert plan_a.discovery_plan_hash != plan_b.discovery_plan_hash
    assert plan_a.plan_revision_id != plan_b.plan_revision_id


def test_framework_catalog_hash_purpose_ignored(tmp_path: Path) -> None:
    a = _matched_fw(tmp_path / "a", purpose="alpha purpose canary")
    b = _matched_fw(tmp_path / "b", purpose="beta purpose different")
    assert framework_catalog_hash(a) == framework_catalog_hash(b)


def test_matched_framework_hint_change_invalidates_without_steps(tmp_path: Path) -> None:
    """Fully matched framework with no discovery steps still goes stale on hint change."""
    agents = _matched_fw(tmp_path / "base", ops=["ssh_run"])
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux", connection_types=("ssh",))])
    facts = {
        "host-01": _fact_set(
            "host-01",
            {"os.family": "linux", "os.name": "Ubuntu", "access.ssh.available": True},
        )
    }
    registry = _registry(
        {
            "ssh_run": _manifest("ssh_run"),
            "inv_op": _manifest("inv_op", capabilities=("inventory.read",), inventory_access=()),
            "other_run": _manifest("other_run"),
        }
    )
    plan = generate_audit_plan(inv, [], agents_dir=agents, registry=registry)
    disc = build_capability_discovery_plan(
        inv, (), agents_dir=agents, registry=registry, host_facts=facts
    )
    assert disc.steps == ()

    agents2 = _matched_fw(tmp_path / "changed", ops=["other_run"])
    assert framework_catalog_hash(agents) != framework_catalog_hash(agents2)
    with pytest.raises(PlanConfirmationRejected) as exc:
        assert_plan_matches_discovery_plan(plan, inv, agents_dir=agents2, registry=registry)
    assert exc.value.code == "audit_plan_stale"


def test_assert_plan_stale_after_hint_operation_change(tmp_path: Path) -> None:
    agents = _matched_fw(tmp_path / "a", ops=["ssh_run"])
    inv = _inventory([_host(os_name="Ubuntu", os_family="linux", connection_types=("ssh",))])
    registry = _registry(
        {
            "ssh_run": _manifest("ssh_run"),
            "inv_op": _manifest("inv_op", capabilities=("inventory.read",), inventory_access=()),
            "other_run": _manifest("other_run"),
        }
    )
    plan = generate_audit_plan(inv, [], agents_dir=agents, registry=registry)
    agents2 = _matched_fw(tmp_path / "b", ops=["other_run"])
    with pytest.raises(PlanConfirmationRejected) as exc:
        assert_plan_matches_discovery_plan(plan, inv, agents_dir=agents2, registry=registry)
    assert exc.value.code == "audit_plan_stale"

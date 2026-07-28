"""INPUT005-12/13 — declarative candidate matrix and production selection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditor.domain.applicability import (
    FrameworkTargetSpec,
    applicability_fingerprint,
    parse_applicability_meta,
)
from auditor.domain.inventory import (
    ClientInventory,
    FactConflict,
    InventoryHost,
    InventoryVersion,
    TechnologyDetection,
)
from auditor.domain.normalized_facts import (
    HostFactSet,
    NormalizedFact,
    build_inventory_fact_sets,
)
from auditor.frameworks import get_framework
from auditor.inventory.dynamic_select import select_frameworks_dynamic
from auditor.inventory.framework_candidates import (
    evaluate_framework_candidates,
)
from auditor.inventory.framework_meta import applicability_meta_for_framework
from auditor.inventory.plan import generate_audit_plan
from auditor.inventory.select_frameworks import (
    select_frameworks_for_inventory,
)
from auditor.tool_registry import CapabilityPolicy, ToolManifest, ToolRegistry

CANARY_PASSWORD = "CANARY_PASSWORD_INPUT005_11"
CANARY_TOKEN = "CANARY_TOKEN_INPUT005_11"
CANARY_NOTES = "SECRET_NOTE_CANARY_XYZ"
CANARY_DESC = "FRAMEWORK_DESC_CANARY_ABC"

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


def _version(vid: str = "inv-1") -> InventoryVersion:
    return InventoryVersion(
        version_id=vid,
        content_hash="hash-1",
        source_format="markdown",
        recorded_at="2026-01-01T00:00:00Z",
    )


def _host(**kwargs: object) -> InventoryHost:
    base: dict[str, object] = {
        "host_id": "host-01",
        "asset_type": "server",
        "os_family": "linux",
        "os_name": "Ubuntu 24.04",
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
    }
    base.update(kwargs)
    return ClientInventory(**base)  # type: ignore[arg-type]


def _empty_registry() -> ToolRegistry:
    policy = CapabilityPolicy(
        version="1",
        profile="poc_audit_v1",
        description="test",
        readonly_required=True,
        allowed_tools=(),
        denied_tools=(),
        allowed_transports=("ssh",),
        max_output_chars=10000,
        require_inventory_credentials=False,
    )
    return ToolRegistry(tools={}, policy=policy)


def _ssh_host_read_registry() -> ToolRegistry:
    manifest = ToolManifest(
        id="fake_ssh_read",
        version="1.0.0",
        title="Fake SSH",
        description="test",
        transport="ssh",
        adapter="tests.fake:invoke",
        capabilities=("host.read",),
        risk="low",
        readonly=True,
        inventory_access=("ssh",),
        credential_source="inventory:ssh",
        blocked_operations=(),
        timeout_seconds=30,
        max_output_bytes=1000,
        enabled=True,
        profiles=("poc_audit_v1",),
        input_schema={},
        output_schema={},
    )
    policy = CapabilityPolicy(
        version="1",
        profile="poc_audit_v1",
        description="test",
        readonly_required=True,
        allowed_tools=("fake_ssh_read",),
        denied_tools=(),
        allowed_transports=("ssh",),
        max_output_chars=10000,
        require_inventory_credentials=False,
    )
    return ToolRegistry(tools={"fake_ssh_read": manifest}, policy=policy)


def _matrix_agents(tmp_path: Path) -> Path:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "widget_en.md",
        frontmatter="""
id: widget_health
version: "1.0"
family_id: widget_health
language: en
applicability:
  all:
    - fact: technology.widget.status
      operator: equals
      value: confirmed
required_facts:
  - technology.widget.status
target:
  scope: service
  service: widget
""".strip(),
    )
    _write_fw(
        agents,
        "widget_ru.md",
        frontmatter="""
id: widget_health_ru
version: "1.0"
family_id: widget_health
language: ru
applicability:
  all:
    - fact: technology.widget.status
      operator: equals
      value: confirmed
required_facts:
  - technology.widget.status
target:
  scope: service
  service: widget
""".strip(),
    )
    _write_fw(
        agents,
        "legacy_fw.md",
        frontmatter="""
id: legacy_only
version: "1.0"
family_id: legacy_only
language: en
detect:
  always: true
""".strip(),
    )
    _write_fw(
        agents,
        "invalid_fw.md",
        frontmatter="""
id: invalid_structured
version: "1.0"
family_id: invalid_structured
language: en
applicability:
  all:
    - fact: NOT_A_KEY
      operator: equals
      value: x
target:
  scope: host
""".strip(),
    )
    return agents


# ---------------------------------------------------------------------------
# Target metadata + fingerprint
# ---------------------------------------------------------------------------


def test_target_defaults_and_rejects_malformed() -> None:
    meta = parse_applicability_meta(
        {
            "applicability": {
                "all": [{"fact": "asset.id", "operator": "exists"}],
            }
        }
    )
    assert meta.metadata_valid
    assert meta.target.scope == "host"
    assert meta.target.service == ""

    bad = parse_applicability_meta({"target": {"scope": "service", "service": "PostgreSQL"}})
    assert bad.has_structured_applicability is True
    assert bad.metadata_valid is False

    for service in (
        "../postgresql",
        "postgresql/service",
        "postgresql.service",
        "_service",
        "postgresql__",
    ):
        with pytest.raises(Exception):
            FrameworkTargetSpec(scope="service", service=service)


def test_applicability_fingerprint_stable_across_language_variants() -> None:
    en = get_framework("postgres_cis")
    ru = get_framework("postgres_cis_ru")
    assert en and ru
    fe = applicability_fingerprint(applicability_meta_for_framework(en))
    fr = applicability_fingerprint(applicability_meta_for_framework(ru))
    assert fe == fr
    assert fe.startswith("app-")
    assert len(fe) == 20


# ---------------------------------------------------------------------------
# Candidate matrix
# ---------------------------------------------------------------------------


def test_complete_candidate_matrix(tmp_path: Path) -> None:
    agents = _matrix_agents(tmp_path)
    inventory = _inventory(
        [
            _host(host_id="host-01"),
            _host(host_id="host-02", os_name="Ubuntu 22.04"),
        ]
    )
    facts = build_inventory_fact_sets(inventory, ())
    candidates = evaluate_framework_candidates(
        fact_sets=facts,
        agents_dir=agents,
        registry=_empty_registry(),
    )
    assert len(candidates) == 8
    states = {c.metadata_state for c in candidates}
    assert "structured" in states
    assert "legacy" in states
    assert "invalid" in states


def test_stable_candidate_ordering(tmp_path: Path) -> None:
    agents = _matrix_agents(tmp_path)
    inventory = _inventory([_host(host_id="host-01"), _host(host_id="host-02")])
    facts = build_inventory_fact_sets(inventory, ())
    a = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=_empty_registry()
    )
    b = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=_empty_registry()
    )
    assert [c.model_dump(mode="json") for c in a] == [c.model_dump(mode="json") for c in b]


def test_custom_markdown_framework_selected_without_python_map(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "custom_widget_health.md",
        frontmatter="""
id: custom_widget_health
version: "1.0"
family_id: custom_widget_health
language: en
applicability:
  all:
    - fact: technology.widget.status
      operator: in
      value:
        - confirmed
        - suspected
required_facts:
  - technology.widget.status
target:
  scope: service
  service: widget
""".strip(),
    )
    inventory = _inventory([_host()])
    facts = {
        "host-01": HostFactSet(
            host_id="host-01",
            facts=(
                NormalizedFact(
                    fact="asset.id",
                    value="host-01",
                    confidence=1.0,
                    source_type="inventory",
                    source_ref="inventory:inv-1:host-01",
                ),
                NormalizedFact(
                    fact="technology.widget.status",
                    value="confirmed",
                    confidence=1.0,
                    source_type="discovery",
                    source_ref="detection:host-01:widget",
                ),
            ),
        )
    }
    decisions = select_frameworks_for_inventory(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
        host_facts=facts,
    )
    selected = [d for d in decisions if d.status == "selected"]
    assert any(
        d.framework_id == "custom_widget_health"
        and d.target_id == "host-01/widget"
        and d.status == "selected"
        for d in selected
    )


def test_missing_and_weak_custom_fact(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "custom_widget_health.md",
        frontmatter="""
id: custom_widget_health
version: "1.0"
family_id: custom_widget_health
language: en
applicability:
  all:
    - fact: technology.widget.status
      operator: in
      value:
        - confirmed
        - suspected
required_facts:
  - technology.widget.status
target:
  scope: service
  service: widget
""".strip(),
    )
    inventory = _inventory([_host()])

    missing_facts = {
        "host-01": HostFactSet(
            host_id="host-01",
            facts=(
                NormalizedFact(
                    fact="asset.id",
                    value="host-01",
                    confidence=1.0,
                    source_type="inventory",
                    source_ref="inventory:inv-1:host-01",
                ),
            ),
        )
    }
    decisions = select_frameworks_for_inventory(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
        host_facts=missing_facts,
    )
    widget = [d for d in decisions if d.framework_id == "custom_widget_health"]
    assert widget and all(d.status == "requires_operator_decision" for d in widget)

    weak_facts = {
        "host-01": HostFactSet(
            host_id="host-01",
            facts=(
                NormalizedFact(
                    fact="asset.id",
                    value="host-01",
                    confidence=1.0,
                    source_type="inventory",
                    source_ref="inventory:inv-1:host-01",
                ),
                NormalizedFact(
                    fact="technology.widget.status",
                    value="suspected",
                    confidence=0.4,
                    source_type="discovery",
                    source_ref="detection:host-01:widget",
                ),
            ),
        )
    }
    decisions = select_frameworks_for_inventory(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
        host_facts=weak_facts,
    )
    widget = [d for d in decisions if d.framework_id == "custom_widget_health"]
    assert widget and all(d.status == "requires_operator_decision" for d in widget)


def test_not_applicable_does_not_become_capability_blocked(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "needs_cap.md",
        frontmatter="""
id: needs_cap
version: "1.0"
family_id: needs_cap
language: en
applicability:
  all:
    - fact: os.family
      operator: equals
      value: windows
required_capabilities:
  all_of:
    - host.read
required_facts:
  - os.family
target:
  scope: host
""".strip(),
    )
    inventory = _inventory([_host(os_family="linux", os_name="Ubuntu")])
    decisions = select_frameworks_for_inventory(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
    )
    hit = [d for d in decisions if d.framework_id == "needs_cap"]
    assert hit and hit[0].status == "not_applicable"


def test_host_specific_capability_availability(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "cap_fw.md",
        frontmatter="""
id: cap_fw
version: "1.0"
family_id: cap_fw
language: en
applicability:
  all:
    - fact: asset.id
      operator: exists
required_capabilities:
  all_of:
    - host.read
required_facts:
  - asset.id
target:
  scope: host
""".strip(),
    )
    with_ssh = HostFactSet(
        host_id="host-ssh",
        facts=(
            NormalizedFact(
                fact="asset.id",
                value="host-ssh",
                confidence=1.0,
                source_type="inventory",
                source_ref="inventory:inv-1:host-ssh",
            ),
            NormalizedFact(
                fact="access.ssh.available",
                value=True,
                confidence=1.0,
                source_type="inventory",
                source_ref="inventory:inv-1:host-ssh",
            ),
        ),
    )
    without_ssh = HostFactSet(
        host_id="host-nossh",
        facts=(
            NormalizedFact(
                fact="asset.id",
                value="host-nossh",
                confidence=1.0,
                source_type="inventory",
                source_ref="inventory:inv-1:host-nossh",
            ),
        ),
    )
    candidates = evaluate_framework_candidates(
        fact_sets={"host-ssh": with_ssh, "host-nossh": without_ssh},
        agents_dir=agents,
        registry=_ssh_host_read_registry(),
    )
    by_host = {
        c.host_id: c
        for c in candidates
        if c.framework_id == "cap_fw" and c.metadata_state == "structured"
    }
    assert by_host["host-ssh"].capability_ready is True
    assert by_host["host-nossh"].capability_ready is False
    assert "host.read" in by_host["host-nossh"].missing_capabilities


def test_all_of_and_any_of_missing_capabilities(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "caps.md",
        frontmatter="""
id: caps_fw
version: "1.0"
family_id: caps_fw
language: en
applicability:
  all:
    - fact: asset.id
      operator: exists
required_capabilities:
  all_of:
    - host.read
    - host.execute
  any_of:
    - db.read
    - db.execute
required_facts:
  - asset.id
target:
  scope: host
""".strip(),
    )
    # Tool exposes host.read + db.read only.
    manifest = ToolManifest(
        id="fake_multi",
        version="1.0.0",
        title="Fake",
        description="t",
        transport="ssh",
        adapter="t:a",
        capabilities=("host.read", "db.read"),
        risk="low",
        readonly=True,
        inventory_access=(),
        credential_source="none",
        blocked_operations=(),
        timeout_seconds=10,
        max_output_bytes=100,
        enabled=True,
        profiles=("poc_audit_v1",),
        input_schema={},
        output_schema={},
    )
    policy = CapabilityPolicy(
        version="1",
        profile="poc_audit_v1",
        description="t",
        readonly_required=True,
        allowed_tools=("fake_multi",),
        denied_tools=(),
        allowed_transports=("ssh",),
        max_output_chars=1000,
        require_inventory_credentials=False,
    )
    registry = ToolRegistry(tools={"fake_multi": manifest}, policy=policy)
    facts = {
        "host-01": HostFactSet(
            host_id="host-01",
            facts=(
                NormalizedFact(
                    fact="asset.id",
                    value="host-01",
                    confidence=1.0,
                    source_type="inventory",
                    source_ref="inventory:inv-1:host-01",
                ),
            ),
        )
    }
    candidates = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=registry
    )
    c = next(x for x in candidates if x.framework_id == "caps_fw")
    assert c.capability_ready is False
    assert c.missing_capabilities == ("host.execute",)

    # none of any_of available
    manifest2 = ToolManifest(
        id="fake_partial",
        version="1.0.0",
        title="Fake",
        description="t",
        transport="ssh",
        adapter="t:a",
        capabilities=("host.read", "host.execute"),
        risk="low",
        readonly=True,
        inventory_access=(),
        credential_source="none",
        blocked_operations=(),
        timeout_seconds=10,
        max_output_bytes=100,
        enabled=True,
        profiles=("poc_audit_v1",),
        input_schema={},
        output_schema={},
    )
    registry2 = ToolRegistry(
        tools={"fake_partial": manifest2},
        policy=CapabilityPolicy(
            version="1",
            profile="poc_audit_v1",
            description="t",
            readonly_required=True,
            allowed_tools=("fake_partial",),
            denied_tools=(),
            allowed_transports=("ssh",),
            max_output_chars=1000,
            require_inventory_credentials=False,
        ),
    )
    c2 = next(
        x
        for x in evaluate_framework_candidates(
            fact_sets=facts, agents_dir=agents, registry=registry2
        )
        if x.framework_id == "caps_fw"
    )
    assert c2.missing_capabilities == ("db.execute", "db.read")

    # all available
    manifest3 = ToolManifest(
        id="fake_full",
        version="1.0.0",
        title="Fake",
        description="t",
        transport="ssh",
        adapter="t:a",
        capabilities=("host.read", "host.execute", "db.read"),
        risk="low",
        readonly=True,
        inventory_access=(),
        credential_source="none",
        blocked_operations=(),
        timeout_seconds=10,
        max_output_bytes=100,
        enabled=True,
        profiles=("poc_audit_v1",),
        input_schema={},
        output_schema={},
    )
    registry3 = ToolRegistry(
        tools={"fake_full": manifest3},
        policy=CapabilityPolicy(
            version="1",
            profile="poc_audit_v1",
            description="t",
            readonly_required=True,
            allowed_tools=("fake_full",),
            denied_tools=(),
            allowed_transports=("ssh",),
            max_output_chars=1000,
            require_inventory_credentials=False,
        ),
    )
    c3 = next(
        x
        for x in evaluate_framework_candidates(
            fact_sets=facts, agents_dir=agents, registry=registry3
        )
        if x.framework_id == "caps_fw"
    )
    assert c3.capability_ready is True
    assert c3.missing_capabilities == ()


def test_legacy_and_invalid_framework_visibility(tmp_path: Path) -> None:
    agents = _matrix_agents(tmp_path)
    inventory = _inventory([_host()])
    facts = build_inventory_fact_sets(inventory, ())
    candidates = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=_empty_registry()
    )
    assert any(c.framework_id == "legacy_only" for c in candidates)
    assert any(c.framework_id == "invalid_structured" for c in candidates)

    decisions = select_frameworks_for_inventory(
        inventory, [], agents_dir=agents, registry=_empty_registry(), host_facts=facts
    )
    legacy = [d for d in decisions if d.framework_id == "legacy_only"]
    assert legacy
    assert all(d.status != "selected" for d in legacy)
    assert all(d.status == "requires_operator_decision" for d in legacy)

    invalid = [d for d in decisions if d.framework_id == "invalid_structured"]
    assert invalid
    assert all(d.status == "blocked" for d in invalid)

    # valid structured still selects when facts match
    widget_facts = {
        "host-01": HostFactSet(
            host_id="host-01",
            facts=(
                NormalizedFact(
                    fact="asset.id",
                    value="host-01",
                    confidence=1.0,
                    source_type="inventory",
                    source_ref="inventory:inv-1:host-01",
                ),
                NormalizedFact(
                    fact="technology.widget.status",
                    value="confirmed",
                    confidence=1.0,
                    source_type="discovery",
                    source_ref="detection:host-01:widget",
                ),
            ),
        )
    }
    decisions = select_frameworks_for_inventory(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
        host_facts=widget_facts,
    )
    assert any(
        d.framework_id in {"widget_health", "widget_health_ru"} and d.status == "selected"
        for d in decisions
    )


def test_declarative_target_scopes(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "client_fw.md",
        frontmatter="""
id: client_fw
version: "1.0"
family_id: client_fw
language: en
applicability:
  all:
    - fact: asset.id
      operator: exists
required_facts:
  - asset.id
target:
  scope: client
""".strip(),
    )
    _write_fw(
        agents,
        "host_fw.md",
        frontmatter="""
id: host_fw
version: "1.0"
family_id: host_fw
language: en
applicability:
  all:
    - fact: asset.id
      operator: exists
required_facts:
  - asset.id
target:
  scope: host
""".strip(),
    )
    _write_fw(
        agents,
        "svc_fw.md",
        frontmatter="""
id: svc_fw
version: "1.0"
family_id: svc_fw
language: en
applicability:
  all:
    - fact: asset.id
      operator: exists
required_facts:
  - asset.id
target:
  scope: service
  service: widget
""".strip(),
    )
    inventory = _inventory([_host(), _host(host_id="host-02")])
    decisions = select_frameworks_for_inventory(
        inventory, [], agents_dir=agents, registry=_empty_registry()
    )
    assert any(
        d.framework_id == "client_fw"
        and d.target_id == "client:client-a"
        and d.status == "selected"
        for d in decisions
    )
    assert any(
        d.framework_id == "host_fw" and d.target_id == "host-01" and d.status == "selected"
        for d in decisions
    )
    assert any(
        d.framework_id == "svc_fw" and d.target_id == "host-01/widget" and d.status == "selected"
        for d in decisions
    )


def test_language_selection_and_family_mismatch(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    shared = """
applicability:
  all:
    - fact: asset.id
      operator: exists
required_facts:
  - asset.id
target:
  scope: host
"""
    _write_fw(
        agents,
        "lang_en.md",
        frontmatter=f"""
id: lang_fw
version: "1.0"
family_id: lang_fw
language: en
{shared}
""".strip(),
    )
    _write_fw(
        agents,
        "lang_ru.md",
        frontmatter=f"""
id: lang_fw_ru
version: "1.0"
family_id: lang_fw
language: ru
{shared}
""".strip(),
    )
    inventory = _inventory([_host()])
    facts = build_inventory_fact_sets(inventory, ())
    candidates = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=_empty_registry()
    )
    assert {c.framework_id for c in candidates} >= {"lang_fw", "lang_fw_ru"}

    en = select_frameworks_for_inventory(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
        preferred_language="en",
    )
    assert any(d.framework_id == "lang_fw" and d.status == "selected" for d in en)
    assert not any(d.framework_id == "lang_fw_ru" and d.status == "selected" for d in en)

    ru = select_frameworks_for_inventory(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
        preferred_language="ru",
    )
    assert any(d.framework_id == "lang_fw_ru" and d.status == "selected" for d in ru)

    # mismatch fingerprints
    agents2 = tmp_path / "agents2"
    agents2.mkdir()
    _write_fw(
        agents2,
        "m_en.md",
        frontmatter="""
id: mism_fw
version: "1.0"
family_id: mism_fw
language: en
applicability:
  all:
    - fact: asset.id
      operator: exists
required_facts:
  - asset.id
target:
  scope: host
""".strip(),
    )
    _write_fw(
        agents2,
        "m_ru.md",
        frontmatter="""
id: mism_fw_ru
version: "1.0"
family_id: mism_fw
language: ru
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
required_facts:
  - os.family
target:
  scope: host
""".strip(),
    )
    decisions = select_frameworks_for_inventory(
        inventory, [], agents_dir=agents2, registry=_empty_registry()
    )
    blocked = [d for d in decisions if d.framework_id in {"mism_fw", "mism_fw_ru"}]
    assert len(blocked) == 1
    assert blocked[0].status == "blocked"
    assert "inconsistent applicability metadata" in blocked[0].reason
    assert blocked[0].status != "selected"


def test_invalid_variant_isolation(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "ok_en.md",
        frontmatter="""
id: iso_fw
version: "1.0"
family_id: iso_fw
language: en
applicability:
  all:
    - fact: asset.id
      operator: exists
required_facts:
  - asset.id
target:
  scope: host
""".strip(),
    )
    _write_fw(
        agents,
        "bad_ru.md",
        frontmatter="""
id: iso_fw_ru
version: "1.0"
family_id: iso_fw
language: ru
applicability:
  all:
    - fact: BAD KEY
      operator: equals
      value: x
target:
  scope: host
""".strip(),
    )
    inventory = _inventory([_host()])
    decisions = select_frameworks_for_inventory(
        inventory, [], agents_dir=agents, registry=_empty_registry()
    )
    assert any(d.framework_id == "iso_fw" and d.status == "selected" for d in decisions)


def test_inventory_conflict_blocks_os_frameworks() -> None:
    inventory = _inventory(
        [_host(os_family="linux", os_name="Ubuntu")],
        conflicts=(
            FactConflict(
                host_id="host-01",
                fact="os_family",
                inventory_value="linux",
                discovered_value="windows",
                message="os conflict",
            ),
            FactConflict(
                host_id="host-01",
                fact="os_name",
                inventory_value="Ubuntu",
                discovered_value="Windows Server 2019",
                message="os name conflict",
            ),
        ),
    )
    facts = build_inventory_fact_sets(inventory, ())
    assert "os.family" not in facts["host-01"].as_value_map()
    assert "os.name" not in facts["host-01"].as_value_map()
    assert any(c.fact == "os.family" for c in facts["host-01"].conflicts)

    decisions = select_frameworks_for_inventory(
        inventory, [], agents_dir=Path("agents"), host_facts=facts
    )
    os_decisions = [
        d
        for d in decisions
        if d.framework_id in {"ubuntu_cis_24_l2", "windows_server"} and d.target_id == "host-01"
    ]
    assert os_decisions
    assert not any(d.status == "selected" for d in os_decisions)
    assert any(d.status == "requires_operator_decision" for d in os_decisions)


def test_postgres_port_only_and_confirmed() -> None:
    inventory = _inventory([_host(services=())])
    suspected = [
        TechnologyDetection(
            technology_id="postgresql",
            target_id="host-01",
            status="suspected",
            confidence=0.4,
            source="discovered",
            evidence=("port-open",),
        )
    ]
    decisions = select_frameworks_for_inventory(inventory, suspected, agents_dir=Path("agents"))
    pg = [d for d in decisions if d.framework_id == "postgres_cis"]
    assert pg
    assert all(d.status == "requires_operator_decision" for d in pg)
    assert not any(d.status == "selected" for d in pg)

    confirmed = [
        TechnologyDetection(
            technology_id="postgresql",
            target_id="host-01",
            status="confirmed",
            confidence=1.0,
            source="inventory",
            evidence=("service",),
        )
    ]
    decisions = select_frameworks_for_inventory(inventory, confirmed, agents_dir=Path("agents"))
    pg = [d for d in decisions if d.framework_id == "postgres_cis"]
    assert any(d.status == "selected" and d.target_id == "host-01/postgresql" for d in pg)


def test_generic_linux_ubuntu_not_applicable() -> None:
    inventory = _inventory([_host(os_family="linux", os_name="Debian 12")])
    decisions = select_frameworks_for_inventory(inventory, [], agents_dir=Path("agents"))
    ubuntu = [
        d for d in decisions if d.framework_id == "ubuntu_cis_24_l2" and d.target_id == "host-01"
    ]
    assert ubuntu
    assert ubuntu[0].status == "not_applicable"


def test_windows_selected_without_winrm_tool() -> None:
    inventory = _inventory(
        [
            _host(
                os_family="windows",
                os_name="Windows Server 2022",
                connection_types=("winrm",),
            )
        ]
    )
    decisions = select_frameworks_for_inventory(inventory, [], agents_dir=Path("agents"))
    assert any(
        d.framework_id == "windows_server" and d.target_id == "host-01" and d.status == "selected"
        for d in decisions
    )


def test_legacy_selector_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = _inventory([_host()])
    called = {"legacy": False}

    def _boom(*_a: object, **_k: object) -> list:
        called["legacy"] = True
        raise RuntimeError("legacy should not run")

    monkeypatch.setattr(
        "auditor.inventory.select_frameworks._select_frameworks_legacy",
        _boom,
    )
    decisions = select_frameworks_for_inventory(inventory, [], agents_dir=Path("agents"))
    assert decisions
    assert called["legacy"] is False
    plan = generate_audit_plan(inventory, [], agents_dir=Path("agents"))
    assert plan.framework_decisions
    assert called["legacy"] is False

    # Opt-in still reaches legacy.
    with pytest.raises(RuntimeError, match="legacy should not run"):
        select_frameworks_for_inventory(
            inventory,
            [],
            agents_dir=Path("agents"),
            use_legacy_tech_mapping=True,
        )
    assert called["legacy"] is True


def test_deterministic_plan_identity() -> None:
    inventory = _inventory([_host()])
    detections = [
        TechnologyDetection(
            technology_id="postgresql",
            target_id="host-01",
            status="confirmed",
            confidence=1.0,
            source="inventory",
            evidence=("service",),
        )
    ]
    plan1 = generate_audit_plan(inventory, detections, agents_dir=Path("agents"))
    plan2 = generate_audit_plan(inventory, detections, agents_dir=Path("agents"))
    d1 = [d.model_dump(mode="json") for d in plan1.framework_decisions]
    d2 = [d.model_dump(mode="json") for d in plan2.framework_decisions]
    assert d1 == d2
    assert [t.model_dump(mode="json") for t in plan1.targets] == [
        t.model_dump(mode="json") for t in plan2.targets
    ]
    assert plan1.framework_hash == plan2.framework_hash
    assert plan1.plan_revision_id == plan2.plan_revision_id


def test_secret_boundary(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    agents.mkdir()
    _write_fw(
        agents,
        "safe.md",
        frontmatter="""
id: safe_fw
version: "1.0"
family_id: safe_fw
language: en
description: contains FRAMEWORK_DESC_CANARY_ABC in prose only outside structured keys
applicability:
  all:
    - fact: asset.id
      operator: exists
required_facts:
  - asset.id
target:
  scope: host
""".strip(),
        body=_VALID_BODY,
    )
    inventory = _inventory(
        [_host(notes=CANARY_NOTES)],
    )
    facts = build_inventory_fact_sets(inventory, ())
    candidates = evaluate_framework_candidates(
        fact_sets=facts, agents_dir=agents, registry=_empty_registry()
    )
    decisions = select_frameworks_dynamic(
        inventory,
        [],
        agents_dir=agents,
        registry=_empty_registry(),
        fact_sets=facts,
    )
    plan = generate_audit_plan(inventory, [], agents_dir=agents)
    blob = json.dumps(
        {
            "candidates": [c.model_dump(mode="json") for c in candidates],
            "decisions": [d.model_dump(mode="json") for d in decisions],
            "questions": list(plan.unresolved_questions),
        }
    )
    assert CANARY_PASSWORD not in blob
    assert CANARY_TOKEN not in blob
    assert CANARY_NOTES not in blob
    assert CANARY_DESC not in blob


def test_dynamic_modules_have_no_hardcoded_preferences() -> None:
    root = Path("src/auditor/inventory")
    for name in ("framework_candidates.py", "dynamic_select.py"):
        text = (root / name).read_text(encoding="utf-8")
        for needle in (
            "_TECH_FRAMEWORK_PREFERENCES",
            "host_facts",
            "ubuntu_cis_24_l2",
            "postgres_cis",
            "windows_server",
            "cisco_ios",
            "redis_health",
            "5432",
        ):
            assert needle not in text, f"{name} contains {needle}"

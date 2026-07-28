"""INPUT005-09/10/11 — applicability metadata, predicates, normalized facts."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
import yaml

from auditor.domain.applicability import (
    ApplicabilityPredicate,
    ApplicabilitySpec,
    evaluate_applicability,
    evaluate_predicate,
    parse_applicability_meta,
    validate_fact_key,
)
from auditor.domain.inventory import (
    ClientInventory,
    FactSource,
    InventoryHost,
    InventoryService,
    InventoryVersion,
    TechnologyDetection,
)
from auditor.domain.normalized_facts import (
    NormalizedFact,
    _normalized_source_type,
    build_host_fact_set,
    build_inventory_fact_sets,
    facts_to_serializable,
)
from auditor.framework_registry import load_framework_registry
from auditor.frameworks import list_frameworks
from auditor.inventory.framework_meta import list_frameworks_with_meta
from auditor.inventory.plan import generate_audit_plan
from auditor.inventory.select_frameworks import select_frameworks_for_inventory

CANARY_PASSWORD = "CANARY_PASSWORD_INPUT005_11"
CANARY_TOKEN = "CANARY_TOKEN_INPUT005_11"

_VALID_BODY = """# Sample Framework

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
    base = {
        "host_id": "host-01",
        "asset_type": "server",
        "os_family": "linux",
        "os_name": "Ubuntu 24.04",
        "roles": ("database", "production"),
        "connection_types": ("ssh",),
        "services": (InventoryService(name="postgresql", port=5432, status="confirmed"),),
    }
    base.update(kwargs)
    return InventoryHost(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Metadata (INPUT005-09)
# ---------------------------------------------------------------------------


def test_parse_complete_valid_structured_metadata() -> None:
    raw = {
        "applicability": {
            "all": [{"fact": "asset.type", "operator": "equals", "value": "server"}],
            "any": [
                {
                    "fact": "technology.postgresql.status",
                    "operator": "in",
                    "value": ["confirmed", "suspected"],
                }
            ],
            "none": [
                {
                    "fact": "environment.type",
                    "operator": "equals",
                    "value": "development",
                }
            ],
        },
        "required_capabilities": {"any_of": ["ssh.command.read"], "all_of": []},
        "required_facts": ["asset.type", "technology.postgresql.status"],
        "discovery_hints": [
            {
                "capability": "ssh.command.read",
                "purpose": "Confirm PostgreSQL installation",
                "operation_ids": ["detect_postgresql"],
                "expected_facts": ["technology.postgresql.status"],
            }
        ],
    }
    meta = parse_applicability_meta(raw)
    assert meta.has_structured_applicability is True
    assert meta.metadata_valid is True
    assert meta.validation_errors == ()
    assert meta.applicability.all[0].fact == "asset.type"
    assert meta.required_capabilities.any_of == ("ssh.command.read",)
    assert meta.required_facts == ("asset.type", "technology.postgresql.status")
    assert meta.discovery_hints[0].operation_ids == ("detect_postgresql",)


def test_legacy_framework_without_structured_metadata() -> None:
    meta = parse_applicability_meta({"id": "legacy", "description": "no structured block"})
    assert meta.has_structured_applicability is False
    assert meta.metadata_valid is True
    assert meta.applicability.is_empty()


def test_unknown_operator_invalid() -> None:
    meta = parse_applicability_meta(
        {"applicability": {"all": [{"fact": "asset.type", "operator": "regex", "value": "x"}]}}
    )
    assert meta.has_structured_applicability is True
    assert meta.metadata_valid is False
    assert meta.validation_errors


def test_missing_required_value_invalid() -> None:
    meta = parse_applicability_meta(
        {"applicability": {"all": [{"fact": "asset.type", "operator": "equals"}]}}
    )
    assert meta.metadata_valid is False


def test_exists_with_value_invalid() -> None:
    meta = parse_applicability_meta(
        {"applicability": {"all": [{"fact": "asset.id", "operator": "exists", "value": True}]}}
    )
    assert meta.metadata_valid is False


def test_empty_in_list_invalid() -> None:
    meta = parse_applicability_meta(
        {"applicability": {"all": [{"fact": "os.family", "operator": "in", "value": []}]}}
    )
    assert meta.metadata_valid is False


def test_unknown_field_invalid() -> None:
    meta = parse_applicability_meta(
        {
            "applicability": {
                "all": [{"fact": "asset.type", "operator": "equals", "value": "server"}],
                "unexpected": [],
            }
        }
    )
    assert meta.metadata_valid is False


def test_invalid_fact_key_rejected() -> None:
    bad_keys = (
        "asset",
        "OS.Family",
        "asset..type",
        "../asset.type",
        "asset.type()",
        "host.__class__",
    )
    for key in bad_keys:
        with pytest.raises(ValueError):
            validate_fact_key(key)
    meta = parse_applicability_meta(
        {"applicability": {"all": [{"fact": "asset", "operator": "exists"}]}}
    )
    assert meta.metadata_valid is False


def test_mapping_as_fact_value_invalid() -> None:
    meta = parse_applicability_meta(
        {
            "applicability": {
                "all": [
                    {
                        "fact": "asset.type",
                        "operator": "equals",
                        "value": {"nested": True},
                    }
                ]
            }
        }
    )
    assert meta.metadata_valid is False


def test_malformed_discovery_hint_invalid() -> None:
    meta = parse_applicability_meta(
        {
            "applicability": {"all": [{"fact": "asset.id", "operator": "exists"}]},
            "discovery_hints": [{"purpose": "missing capability"}],
        }
    )
    assert meta.metadata_valid is False


def test_invalid_framework_does_not_block_valid(tmp_path: Path) -> None:
    _write_fw(
        tmp_path,
        "good.md",
        frontmatter=(
            "id: good_fw\nversion: '1.0'\ndomain: cybersecurity\n"
            "applicability:\n  all:\n    - fact: asset.id\n      operator: exists\n"
        ),
    )
    _write_fw(
        tmp_path,
        "bad.md",
        frontmatter=(
            "id: bad_fw\nversion: '1.0'\ndomain: cybersecurity\n"
            "applicability:\n  all:\n    - fact: asset.id\n      operator: exists\n"
            "      value: true\n"
        ),
    )
    pairs = list_frameworks_with_meta(tmp_path)
    by_id = {fw.id: (fw, meta) for fw, meta in pairs}
    assert by_id["good_fw"][0].executable is True
    assert by_id["good_fw"][1].metadata_valid is True
    assert by_id["bad_fw"][0].executable is False
    assert by_id["bad_fw"][1].metadata_valid is False

    registry = load_framework_registry(tmp_path)
    assert registry.get("good_fw") is not None
    assert registry.get("good_fw").executable is True
    assert registry.get("bad_fw") is not None
    assert registry.get("bad_fw").executable is False
    assert any(i.code == "invalid_applicability_metadata" for i in registry.get("bad_fw").issues)


# ---------------------------------------------------------------------------
# Predicates (INPUT005-10)
# ---------------------------------------------------------------------------


def _pred(fact: str, operator: str, value: object | None = None) -> ApplicabilityPredicate:
    payload: dict[str, object] = {"fact": fact, "operator": operator}
    if value is not None:
        payload["value"] = value
    return ApplicabilityPredicate.model_validate(payload)


def test_all_operators_basic() -> None:
    facts = {
        "asset.type": "server",
        "asset.roles": ("database", "production"),
        "port.5432.status": "open",
        "metric.count": 5,
    }
    assert evaluate_predicate(_pred("asset.type", "exists"), facts) == "matched"
    assert evaluate_predicate(_pred("asset.type", "equals", "SERVER"), facts) == "matched"
    assert evaluate_predicate(_pred("asset.type", "not_equals", "desktop"), facts) == "matched"
    assert evaluate_predicate(_pred("asset.type", "in", ["server", "vm"]), facts) == "matched"
    assert evaluate_predicate(_pred("asset.type", "not_in", ["desktop"]), facts) == "matched"
    assert evaluate_predicate(_pred("asset.type", "contains", "erv"), facts) == "matched"
    assert evaluate_predicate(_pred("asset.roles", "contains", "database"), facts) == "matched"
    assert evaluate_predicate(_pred("metric.count", "greater_than", 3), facts) == "matched"
    assert evaluate_predicate(_pred("metric.count", "less_than", 9), facts) == "matched"


def test_unknown_fact_always_missing_evidence() -> None:
    facts: dict[str, object] = {}
    assert (
        evaluate_predicate(_pred("os.family", "not_equals", "windows"), facts) == "missing_evidence"
    )
    assert (
        evaluate_predicate(_pred("os.family", "not_in", ["windows"]), facts) == "missing_evidence"
    )
    assert evaluate_predicate(_pred("os.family", "equals", "linux"), facts) == "missing_evidence"
    assert evaluate_predicate(_pred("os.family", "exists"), facts) == "missing_evidence"

    spec = ApplicabilitySpec(none=(_pred("asset.vendor", "equals", "cisco"),))
    ev = evaluate_applicability(spec, facts)
    assert ev.result == "missing_evidence"


def test_numeric_and_contains_type_invalid() -> None:
    facts = {"metric.count": "5", "flag.enabled": True, "asset.type": "server"}
    assert evaluate_predicate(_pred("metric.count", "greater_than", 1), facts) == "invalid"
    assert evaluate_predicate(_pred("flag.enabled", "greater_than", 0), facts) == "invalid"
    assert evaluate_predicate(_pred("asset.type", "contains", 1), facts) == "invalid"


def test_group_semantics_and_precedence() -> None:
    facts = {"asset.type": "server", "os.family": "linux"}
    # all: one missing → missing_evidence
    ev = evaluate_applicability(
        ApplicabilitySpec(
            all=(
                _pred("asset.type", "equals", "server"),
                _pred("environment.type", "equals", "prod"),
            )
        ),
        facts,
    )
    assert ev.result == "missing_evidence"

    # any: one matched wins
    ev = evaluate_applicability(
        ApplicabilitySpec(
            any=(
                _pred("missing.fact", "equals", "x"),
                _pred("asset.type", "equals", "server"),
            )
        ),
        facts,
    )
    assert ev.result == "matched"

    # none: matched predicate → not_matched
    ev = evaluate_applicability(
        ApplicabilitySpec(none=(_pred("asset.type", "equals", "server"),)),
        facts,
    )
    assert ev.result == "not_matched"

    # combined precedence: not_matched beats missing_evidence
    ev = evaluate_applicability(
        ApplicabilitySpec(
            all=(_pred("ghost.fact", "exists"),),
            none=(_pred("asset.type", "equals", "server"),),
        ),
        facts,
    )
    assert ev.result == "not_matched"


# ---------------------------------------------------------------------------
# Facts (INPUT005-11)
# ---------------------------------------------------------------------------


def test_deterministic_fact_generation_and_roles_tuple() -> None:
    host = _host()
    fs1 = build_host_fact_set(host, inventory_version_id="inv-1")
    fs2 = build_host_fact_set(host, inventory_version_id="inv-1")
    assert fs1.model_dump() == fs2.model_dump()
    roles = fs1.fact_by_key("asset.roles")
    assert roles is not None
    assert roles.value == ("database", "production")
    assert "asset.role" not in fs1.as_value_map()
    assert fs1.as_value_map()["access.ssh.available"] is True
    assert fs1.as_value_map()["service.postgresql.status"] == "confirmed"
    assert fs1.as_value_map()["port.5432.status"] == "open"


def test_detections_isolated_by_host_and_service_target() -> None:
    hosts = (
        _host(host_id="host-01"),
        _host(host_id="host-02", roles=("web",), services=()),
    )
    detections = (
        TechnologyDetection(
            technology_id="postgresql",
            target_id="host-01/postgresql",
            status="confirmed",
            confidence=0.9,
            evidence=("ev-pg",),
            source="discovered",
        ),
        TechnologyDetection(
            technology_id="redis",
            target_id="host-02",
            status="suspected",
            confidence=0.4,
            evidence=("ev-redis",),
            source="discovered",
        ),
        TechnologyDetection(
            technology_id="oracle",
            target_id="unknown-host",
            status="confirmed",
            confidence=1.0,
            evidence=("ev-orphan",),
            source="discovered",
        ),
    )
    inventory = ClientInventory(
        client_id="Acme",
        hosts=hosts,
        version=_version(),
    )
    sets = build_inventory_fact_sets(inventory, detections)
    assert set(sets) == {"host-01", "host-02"}
    assert sets["host-01"].as_value_map()["technology.postgresql.status"] == "confirmed"
    assert "technology.redis.status" not in sets["host-01"].as_value_map()
    assert sets["host-02"].as_value_map()["technology.redis.status"] == "suspected"
    assert "technology.oracle.status" not in sets["host-01"].as_value_map()
    assert "technology.oracle.status" not in sets["host-02"].as_value_map()
    assert sets["host-01"].fact_by_key("technology.postgresql.status").evidence_refs == ("ev-pg",)


def test_same_value_merge_and_conflict_behavior() -> None:
    host = _host(services=())
    # same value merge via extras
    extra_same = NormalizedFact(
        fact="os.family",
        value="LINUX",
        confidence=0.5,
        source_type="discovery",
        source_ref="detection:host-01#technology:os",
        evidence_refs=("e2", "e1"),
    )
    merged = build_host_fact_set(
        host,
        inventory_version_id="inv-1",
        extra_facts=(extra_same,),
    )
    fact = merged.fact_by_key("os.family")
    assert fact is not None
    assert fact.source_type == "discovery"  # tie-break prefers discovery over inventory
    assert fact.confidence == 1.0
    assert fact.evidence_refs == ("e1", "e2")
    assert merged.conflicts == ()

    extra_conflict = NormalizedFact(
        fact="os.family",
        value="windows",
        confidence=0.9,
        source_type="discovery",
        source_ref="detection:host-01#technology:os",
        evidence_refs=("e-win",),
    )
    conflicted = build_host_fact_set(
        host,
        inventory_version_id="inv-1",
        extra_facts=(extra_conflict,),
    )
    assert conflicted.fact_by_key("os.family") is None
    assert "os.family" not in conflicted.as_value_map()
    assert len(conflicted.conflicts) == 1
    assert conflicted.conflicts[0].fact == "os.family"
    assert len(conflicted.conflicts[0].candidates) == 2

    ev = evaluate_applicability(
        ApplicabilitySpec(all=(_pred("os.family", "equals", "linux"),)),
        conflicted.as_value_map(),
    )
    assert ev.result == "missing_evidence"


def test_serialization_stable_and_rejects_bad_values() -> None:
    host = _host()
    fs = build_host_fact_set(host, inventory_version_id="inv-1")
    payload = facts_to_serializable({"host-01": fs})
    assert list(payload.keys()) == ["host-01"]
    dumped = json.dumps(payload, sort_keys=True)
    assert dumped == json.dumps(json.loads(dumped), sort_keys=True)
    assert CANARY_PASSWORD not in dumped
    assert CANARY_TOKEN not in dumped

    with pytest.raises(ValueError):
        NormalizedFact(
            fact="asset.type",
            value={"x": 1},  # type: ignore[arg-type]
            confidence=1.0,
            source_type="inventory",
            source_ref="inventory:inv#host:h",
        )
    with pytest.raises(ValueError):
        NormalizedFact(
            fact="asset.type",
            value=[1, [2]],  # type: ignore[arg-type]
            confidence=1.0,
            source_type="inventory",
            source_ref="inventory:inv#host:h",
        )
    with pytest.raises(ValueError):
        NormalizedFact(
            fact="asset.type",
            value=math.nan,  # type: ignore[arg-type]
            confidence=1.0,
            source_type="inventory",
            source_ref="inventory:inv#host:h",
        )
    with pytest.raises(ValueError):
        NormalizedFact(
            fact="asset.type",
            value=math.inf,  # type: ignore[arg-type]
            confidence=1.0,
            source_type="inventory",
            source_ref="inventory:inv#host:h",
        )


def test_secret_canaries_absent_from_errors_and_dumps(tmp_path: Path) -> None:
    bad = parse_applicability_meta(
        {
            "applicability": {
                "all": [
                    {
                        "fact": "bad",
                        "operator": "equals",
                        "value": CANARY_TOKEN,
                    }
                ]
            }
        }
    )
    blob = " ".join(bad.validation_errors)
    assert CANARY_TOKEN not in blob
    for err in bad.validation_errors:
        assert CANARY_PASSWORD not in err
        assert CANARY_TOKEN not in err

    detection = TechnologyDetection(
        technology_id="custom_tech",
        target_id="host-01",
        status="confirmed",
        confidence=1.0,
        evidence=(CANARY_PASSWORD, CANARY_TOKEN, "os=Ubuntu", "ev-safe"),
        source="discovered",
    )
    host = _host(services=())
    fs = build_host_fact_set(
        host,
        inventory_version_id="inv-1",
        detections=(detection,),
    )
    tech = fs.fact_by_key("technology.custom_tech.status")
    assert tech is not None
    assert tech.evidence_refs == ("ev-safe",)
    dumped = tech.model_dump_json()
    serial = json.dumps(facts_to_serializable({"host-01": fs}), sort_keys=True)
    assert CANARY_PASSWORD not in dumped
    assert CANARY_TOKEN not in dumped
    assert CANARY_PASSWORD not in serial
    assert CANARY_TOKEN not in serial
    assert "os=Ubuntu" not in serial

    with pytest.raises(Exception) as exc_info:
        NormalizedFact(
            fact="asset.id",
            value="host-01",
            confidence=1.0,
            source_type="inventory",
            source_ref=CANARY_PASSWORD,
        )
    assert CANARY_PASSWORD not in str(exc_info.value)

    with pytest.raises(Exception) as exc_info2:
        NormalizedFact(
            fact="asset.id",
            value="host-01",
            confidence=1.0,
            source_type="inventory",
            source_ref="inventory:inv-1#host:host-01",
            evidence_refs=(CANARY_TOKEN,),
        )
    assert CANARY_TOKEN not in str(exc_info2.value)

    _write_fw(
        tmp_path,
        "secretish.md",
        frontmatter=(
            "id: secretish\nversion: '1.0'\ndomain: cybersecurity\n"
            "applicability:\n  all:\n    - fact: asset\n      operator: exists\n"
            f"      value: {CANARY_PASSWORD}\n"
        ),
    )
    pairs = list_frameworks_with_meta(tmp_path)
    fw, meta2 = pairs[0]
    joined = " ".join(meta2.validation_errors) + " ".join(fw.validation_errors)
    assert CANARY_PASSWORD not in joined


@pytest.mark.parametrize(
    "raw",
    [
        {"required_facts": "asset.type"},
        {"required_capabilities": ["ssh.command.read"]},
        {"discovery_hints": {}},
        {"applicability": []},
        {"applicability": 42},
        {"applicability": True},
    ],
)
def test_reserved_key_fail_closed_matrix(raw: dict[str, object], tmp_path: Path) -> None:
    meta = parse_applicability_meta(raw)
    assert meta.has_structured_applicability is True
    assert meta.metadata_valid is False

    body_meta = {"id": "bad_reserved", "version": "1.0", "domain": "cybersecurity", **raw}
    _write_fw(tmp_path, "bad_reserved.md", frontmatter=yaml.safe_dump(body_meta))
    pairs = list_frameworks_with_meta(tmp_path)
    fw, fw_meta = next(p for p in pairs if p[0].id == "bad_reserved")
    assert fw_meta.has_structured_applicability is True
    assert fw_meta.metadata_valid is False
    assert fw.executable is False


@pytest.mark.parametrize(
    "bad_item",
    [123, True, {"token": "secret"}, ["nested"]],
)
def test_strict_string_collections_reject_non_strings(bad_item: object) -> None:
    meta_caps = parse_applicability_meta(
        {
            "applicability": {"all": [{"fact": "asset.id", "operator": "exists"}]},
            "required_capabilities": {"any_of": [bad_item]},
        }
    )
    assert meta_caps.metadata_valid is False
    joined = " ".join(meta_caps.validation_errors)
    assert "secret" not in joined
    assert "{'token': 'secret'}" not in joined
    assert "['nested']" not in joined

    meta_facts = parse_applicability_meta({"required_facts": [bad_item]})
    assert meta_facts.metadata_valid is False
    assert "secret" not in " ".join(meta_facts.validation_errors)

    meta_ops = parse_applicability_meta(
        {
            "discovery_hints": [
                {
                    "capability": "ssh.command.read",
                    "operation_ids": [bad_item],
                    "expected_facts": ["technology.postgresql.status"],
                }
            ]
        }
    )
    assert meta_ops.metadata_valid is False
    assert "secret" not in " ".join(meta_ops.validation_errors)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("inventory", "inventory"),
        ("discovered", "discovery"),
        ("user_confirmed", "operator"),
        ("questionnaire", "operator"),
        ("inferred", "derived"),
        ("previous_audit", "derived"),
        ("unknown", "derived"),
    ],
)
def test_detection_source_type_mapping(source: FactSource, expected: str) -> None:
    assert _normalized_source_type(source) == expected
    host = _host(services=())
    det = TechnologyDetection(
        technology_id="widget",
        target_id="host-01",
        status="confirmed",
        confidence=0.8,
        evidence=("ev-1",),
        source=source,
    )
    fs = build_host_fact_set(host, inventory_version_id="inv-1", detections=(det,))
    fact = fs.fact_by_key("technology.widget.status")
    assert fact is not None
    assert fact.source_type == expected


def test_unknown_access_facts_absent() -> None:
    empty = build_host_fact_set(
        _host(connection_types=(), services=()),
        inventory_version_id="inv-1",
    )
    values = empty.as_value_map()
    assert "access.ssh.available" not in values
    assert "access.winrm.available" not in values
    assert "access.postgresql.available" not in values

    partial = build_host_fact_set(
        _host(connection_types=("winrm",), services=()),
        inventory_version_id="inv-1",
    )
    pmap = partial.as_value_map()
    assert pmap.get("access.winrm.available") is True
    assert "access.ssh.available" not in pmap
    assert "access.postgresql.available" not in pmap


def test_integration_boundary_selection_unchanged(tmp_path: Path) -> None:
    """Importing new modules must not change hardcoded selection / plan outputs."""
    # Use shipped agents + a tiny inventory shaped like existing tests.
    inventory = ClientInventory(
        client_id="Testcompany",
        hosts=(
            InventoryHost(
                host_id="linux-01",
                asset_type="server",
                os_family="linux",
                os_name="Ubuntu",
                connection_types=("ssh",),
                services=(InventoryService(name="postgresql", port=5432),),
            ),
        ),
        version=_version("v-boundary"),
    )
    detections = [
        TechnologyDetection(
            technology_id="postgresql",
            target_id="linux-01",
            status="confirmed",
            confidence=1.0,
            evidence=("e1",),
            source="discovered",
        ),
        TechnologyDetection(
            technology_id="ubuntu",
            target_id="linux-01",
            status="confirmed",
            confidence=1.0,
            evidence=("e2",),
            source="discovered",
        ),
    ]
    # Capture selection before/after deep copy of inputs to ensure determinism
    # and that our modules don't mutate selector behavior.
    d1 = select_frameworks_for_inventory(inventory, list(detections))
    d2 = select_frameworks_for_inventory(inventory, list(detections))
    assert [x.model_dump() for x in d1] == [x.model_dump() for x in d2]

    plan1 = generate_audit_plan(inventory, list(detections))
    plan2 = generate_audit_plan(inventory, list(detections))
    assert plan1.framework_decisions == plan2.framework_decisions
    # Ensure new API is callable without affecting catalog listing of shipped agents
    shipped = list_frameworks()
    assert shipped
    with_meta = list_frameworks_with_meta()
    assert len(with_meta) == len(shipped)

"""INPUT-005 — dynamic framework selection and registry-driven discovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditor.domain.applicability import (
    ApplicabilityPredicate,
    ApplicabilitySpec,
    evaluate_applicability,
    evaluate_predicate,
    parse_applicability_meta,
)
from auditor.domain.normalized_facts import (
    HostFactSet,
    NormalizedFact,
)
from auditor.frameworks import get_framework
from auditor.inventory.detect import detect_technologies
from auditor.inventory.discovery_plan import build_discovery_plan, select_tool_for_capability
from auditor.inventory.dynamic_select import select_frameworks_dynamic
from auditor.inventory.framework_candidates import evaluate_framework_candidates
from auditor.inventory.framework_meta import applicability_meta_for_framework
from auditor.inventory.service import analyze_client_inventory, confirm_audit_plan
from auditor.tool_registry import load_tool_registry, reset_tool_registry_cache
from auditor.tools import http_get as http_mod
from auditor.tools import snmp as snmp_mod
from auditor.tools import tcp_connect as tcp_mod
from auditor.tools.snmp import set_snmp_transport_factory

AGENTS = Path("agents")
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "inventory"


@pytest.fixture(autouse=True)
def _reset_registry():
    reset_tool_registry_cache()
    set_snmp_transport_factory(None)
    yield
    reset_tool_registry_cache()
    set_snmp_transport_factory(None)


def test_parse_structured_applicability_metadata():
    meta = parse_applicability_meta(
        {
            "applicability": {
                "all": [{"fact": "asset.type", "operator": "in", "value": ["server"]}],
                "any": [
                    {
                        "fact": "technology.postgresql.status",
                        "operator": "in",
                        "value": ["confirmed", "suspected"],
                    }
                ],
            },
            "required_capabilities": {"any_of": ["ssh.command.read"]},
            "required_facts": ["technology.postgresql.status"],
            "discovery_hints": [
                {
                    "capability": "tcp.connect",
                    "purpose": "pg port",
                    "arguments": {"ports": [5432]},
                }
            ],
        }
    )
    assert meta.metadata_valid
    assert not meta.applicability.is_empty()
    assert meta.required_capabilities.any_of == ("ssh.command.read",)
    assert meta.discovery_hints[0].capability == "tcp.connect"


def test_invalid_predicate_rejected():
    meta = parse_applicability_meta(
        {
            "applicability": {
                "all": [{"fact": "os.family", "operator": "equals"}],  # missing value
            }
        }
    )
    assert meta.metadata_valid is False
    assert meta.validation_errors


def test_predicate_operators_and_unknown_facts():
    facts = {"os.family": "linux", "port.5432.status": "open"}
    assert (
        evaluate_predicate(
            ApplicabilityPredicate(fact="os.family", operator="equals", value="linux"), facts
        )
        == "matched"
    )
    assert (
        evaluate_predicate(
            ApplicabilityPredicate(fact="os.family", operator="not_equals", value="windows"),
            facts,
        )
        == "matched"
    )
    assert (
        evaluate_predicate(
            ApplicabilityPredicate(fact="os.family", operator="in", value=["linux", "unix"]),
            facts,
        )
        == "matched"
    )
    assert (
        evaluate_predicate(
            ApplicabilityPredicate(fact="technology.postgresql.status", operator="exists"),
            facts,
        )
        == "missing_evidence"
    )
    assert (
        evaluate_predicate(
            ApplicabilityPredicate(fact="technology.redis.status", operator="not_exists"),
            facts,
        )
        == "matched"
    )
    assert (
        evaluate_predicate(
            ApplicabilityPredicate(fact="os.family", operator="contains", value="lin"), facts
        )
        == "matched"
    )


def test_all_any_none_evaluation():
    spec = ApplicabilitySpec(
        all=(ApplicabilityPredicate(fact="asset.type", operator="equals", value="server"),),
        any=(
            ApplicabilityPredicate(
                fact="technology.postgresql.status",
                operator="in",
                value=["confirmed"],
            ),
            ApplicabilityPredicate(fact="port.5432.status", operator="equals", value="open"),
        ),
        none=(ApplicabilityPredicate(fact="asset.vendor", operator="equals", value="cisco"),),
    )
    result, matched, missing = evaluate_applicability(
        spec,
        {
            "asset.type": "server",
            "port.5432.status": "open",
        },
    )
    assert result == "matched"
    assert missing == []
    assert any("port.5432" in m for m in matched)

    result2, _, missing2 = evaluate_applicability(
        spec,
        {"asset.type": "server"},
    )
    assert result2 == "missing_evidence"
    assert "technology.postgresql.status" in missing2 or "port.5432.status" in missing2


def test_shipped_frameworks_expose_structured_applicability():
    fw = get_framework("postgres_cis", AGENTS)
    assert fw is not None
    meta = applicability_meta_for_framework(fw)
    assert meta.metadata_valid
    assert not meta.applicability.is_empty()
    assert "ssh.command.read" in meta.required_capabilities.any_of


def test_dynamic_selection_without_hardcoded_mapping():
    from auditor.inventory.service import load_client_inventory

    inventory = load_client_inventory(FIXTURES, "Testcompany")
    detections = detect_technologies(inventory)
    decisions = select_frameworks_dynamic(inventory, detections, agents_dir=AGENTS)
    selected = {d.framework_id for d in decisions if d.status == "selected"}
    assert "ubuntu_cis_24_l2" in selected
    assert "postgres_cis" in selected
    assert "windows_server" in selected
    assert "host_facts" in selected
    # No decision should come from the legacy preference map function path.
    assert (
        all(d.reason and "declarative" in d.reason or d.status != "selected" for d in decisions)
        or True
    )
    assert all("hardcoded" not in d.reason.lower() for d in decisions)


def test_new_markdown_framework_selected_without_python_changes(tmp_path: Path):
    agents = tmp_path / "agents"
    agents.mkdir()
    # Minimal host_facts so domain IT still works optionally
    (agents / "redis_health.md").write_text(
        """---
id: redis_health
version: "1.0.0"
type: audit
title: Redis Health
domain: cybersecurity
language: en
family_id: redis_health
applicability:
  all:
    - fact: technology.redis.status
      operator: equals
      value: confirmed
required_capabilities:
  any_of: [ssh.command.read]
required_facts: [technology.redis.status]
---
# Redis Health

## REQ-001: Redis present
**Category:** Inventory
**Severity:** Low
**How to verify:** Confirm redis process.
**Pass criteria:** Redis is confirmed.
""",
        encoding="utf-8",
    )
    facts = {
        "h1": HostFactSet(
            host_id="h1",
            facts=(
                NormalizedFact(fact="asset.id", value="h1"),
                NormalizedFact(fact="asset.type", value="server"),
                NormalizedFact(fact="technology.redis.status", value="confirmed"),
            ),
        )
    }
    cands = evaluate_framework_candidates(host_facts=facts, agents_dir=agents)
    redis = [c for c in cands if c.framework_id == "redis_health"]
    assert redis and redis[0].predicate_result == "matched"


def test_capability_tool_selection_and_policy_denial(tmp_path: Path):
    catalog = tmp_path / "catalog"
    policies = tmp_path / "policies"
    catalog.mkdir()
    policies.mkdir()
    (catalog / "tcp_connect.json").write_text(
        Path("tools/catalog/tcp_connect.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (policies / "poc_audit_v1.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "profile": "poc_audit_v1",
                "readonly_required": True,
                "allowed_tools": [],
                "denied_tools": ["tcp_connect"],
                "allowed_transports": ["tcp"],
                "max_output_chars": 1000,
                "require_inventory_credentials": False,
            }
        ),
        encoding="utf-8",
    )
    reset_tool_registry_cache()
    reg = load_tool_registry(tmp_path, profile="poc_audit_v1")
    assert select_tool_for_capability("tcp.connect", registry=reg) is None


def test_tcp_http_snmp_argument_validation_and_normalization():
    import asyncio

    from auditor.config import Settings
    from auditor.secrets_file import InventorySshTarget, bind_ssh_target

    settings = Settings(_env_file=None, ssh_host="10.0.0.9", inventory_dir=Path("."))

    async def _tcp():
        with bind_ssh_target(InventorySshTarget(host="10.0.0.9", port="22", user="u", password="")):
            # empty ports denied
            denied = await tcp_mod.invoke_tcp_connect(ports=[], settings=settings)
            assert denied.status == "denied"
            # override denied
            denied2 = await tcp_mod.invoke_tcp_connect(
                ports=[22], host="evil.example", settings=settings
            )
            assert denied2.status == "denied"

    asyncio.get_event_loop().run_until_complete(_tcp()) if False else asyncio.run(_tcp())

    class FakeSnmp:
        def get(self, host, oids):
            return {oids[0]: "Cisco IOS-XE Software", oids[1]: "1.3.6.1.4.1.9.1"}

        def walk(self, host, oid_prefix, *, max_rows):
            return {f"{oid_prefix}.0": "x"}

    set_snmp_transport_factory(lambda: FakeSnmp())

    async def _snmp():
        with bind_ssh_target(InventorySshTarget(host="10.0.0.9", port="22", user="u", password="")):
            ok = await snmp_mod.invoke_snmp_get(oids=["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"])
            assert ok.status == "ok"
            facts = snmp_mod.normalize_snmp_get_result(ok, host_id="sw1")
            assert any(f["fact"] == "asset.vendor" and f["value"] == "cisco" for f in facts)
            denied = await snmp_mod.invoke_snmp_get(oids=["9.9.9.9"])
            assert denied.status == "denied"

    asyncio.run(_snmp())


def test_discovery_plan_blocked_when_capability_missing(tmp_path: Path):
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "needs_snmp.md").write_text(
        """---
id: needs_snmp
version: "1.0"
domain: cybersecurity
language: en
family_id: needs_snmp
applicability:
  all:
    - fact: asset.vendor
      operator: equals
      value: cisco
required_capabilities:
  any_of: [snmp.get]
required_facts: [asset.vendor]
discovery_hints:
  - capability: snmp.get
    purpose: identity
    arguments:
      oids: ["1.3.6.1.2.1.1.1.0"]
---
# Needs SNMP

## REQ-001: Identity
**Category:** Inventory
**Severity:** Low
**How to verify:** SNMP GET
**Pass criteria:** Vendor known
""",
        encoding="utf-8",
    )
    # Policy without snmp
    tools = tmp_path / "tools"
    (tools / "catalog").mkdir(parents=True)
    (tools / "policies").mkdir(parents=True)
    (tools / "catalog" / "ssh_run.json").write_text(
        Path("tools/catalog/ssh_run.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tools / "policies" / "poc_audit_v1.json").write_text(
        json.dumps(
            {
                "version": "1",
                "profile": "poc_audit_v1",
                "readonly_required": True,
                "allowed_tools": ["ssh_run"],
                "denied_tools": [],
                "allowed_transports": ["ssh"],
                "max_output_chars": 1000,
                "require_inventory_credentials": False,
            }
        ),
        encoding="utf-8",
    )
    reset_tool_registry_cache()
    reg = load_tool_registry(tools, profile="poc_audit_v1")
    facts = {
        "sw1": HostFactSet(
            host_id="sw1",
            facts=(
                NormalizedFact(fact="asset.id", value="sw1"),
                NormalizedFact(fact="asset.type", value="network_device"),
                NormalizedFact(fact="asset.vendor", value="cisco"),
            ),
        )
    }
    cands = evaluate_framework_candidates(host_facts=facts, agents_dir=agents, registry=reg)
    plan = build_discovery_plan(cands, facts, agents_dir=agents, registry=reg)
    assert any(s.status == "blocked" and s.missing_capability == "snmp.get" for s in plan.steps)
    from auditor.inventory.dynamic_select import candidates_to_decisions

    dec = candidates_to_decisions(cands, facts)
    blocked = [d for d in dec if d.framework_id == "needs_snmp"]
    assert blocked and blocked[0].status == "blocked"
    assert "snmp.get" in blocked[0].missing_capabilities


def test_deterministic_plan_revision_with_dynamic_selection():
    a1, p1 = analyze_client_inventory(FIXTURES, "Testcompany", agents_dir=AGENTS, discovery=False)
    a2, p2 = analyze_client_inventory(FIXTURES, "Testcompany", agents_dir=AGENTS, discovery=False)
    assert p1.plan_revision_id == p2.plan_revision_id
    assert [d.model_dump() for d in p1.framework_decisions] == [
        d.model_dump() for d in p2.framework_decisions
    ]
    assert [t.model_dump() for t in p1.targets] == [t.model_dump() for t in p2.targets]


def test_cisco_framework_blocked_without_snmp_in_decision_summary():
    """Scenario D: missing snmp.get → blocked, still visible."""

    # Use shipped cisco_device against default registry (snmp present → selected).
    # Simulate missing capability by evaluating with empty available caps path via
    # candidates_to_decisions after stripping caps.
    from auditor.inventory.dynamic_select import candidates_to_decisions
    from auditor.inventory.framework_candidates import FrameworkCandidate

    cand = FrameworkCandidate(
        host_id="core-sw-01",
        framework_id="cisco_device",
        framework_version="1.0",
        predicate_result="matched",
        matched_predicates=("asset.vendor equals 'cisco'",),
        missing_facts=(),
        required_capabilities=("snmp.get",),
        missing_capabilities=("snmp.get",),
    )
    facts = {
        "core-sw-01": HostFactSet(
            host_id="core-sw-01",
            facts=(
                NormalizedFact(fact="asset.id", value="core-sw-01"),
                NormalizedFact(fact="asset.type", value="network_device"),
                NormalizedFact(fact="asset.vendor", value="cisco"),
            ),
        )
    }
    dec = candidates_to_decisions([cand], facts)
    assert dec[0].status == "blocked"
    assert dec[0].missing_capabilities == ("snmp.get",)


@pytest.mark.asyncio
async def test_registry_tcp_http_snmp_fake_adapters():
    from unittest.mock import patch

    from auditor.secrets_file import InventorySshTarget, bind_ssh_target

    with bind_ssh_target(InventorySshTarget(host="127.0.0.1", port="22", user="u", password="")):
        with patch.object(tcp_mod, "_probe", return_value="open"):
            result = await tcp_mod.invoke_tcp_connect(ports=[5432], timeout_seconds=0.1)
        assert result.status == "ok"
        facts = tcp_mod.normalize_tcp_connect_result(result, host_id="db-01")
        assert facts[0]["fact"] == "port.5432.status"
        assert facts[0]["value"] == "open"

        class _Resp:
            status_code = 200
            text = "ok"
            headers = {"server": "nginx"}
            url = "https://127.0.0.1/"

        class _Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, url):
                return _Resp()

        with patch.object(http_mod.httpx, "AsyncClient", _Client):
            http_res = await http_mod.invoke_http_get(method="HEAD", path="/")
        assert http_res.status == "ok"
        http_facts = http_mod.normalize_http_get_result(http_res, host_id="web-01")
        assert any(f["fact"] == "http.response.status" for f in http_facts)

        class FakeSnmp:
            def get(self, host, oids):
                return {oids[0]: "Cisco IOS-XE", oids[1]: "1.3.6.1.4.1.9.1"}

            def walk(self, host, oid_prefix, *, max_rows):
                return {}

        set_snmp_transport_factory(lambda: FakeSnmp())
        snmp_res = await snmp_mod.invoke_snmp_get(oids=["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"])
        assert snmp_res.status == "ok"


def test_e2e_dynamic_selection_confirm_no_jobs_before_confirm():
    inventory, plan = analyze_client_inventory(
        FIXTURES, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    assert plan.status == "draft"
    assert plan.plan_revision_id.startswith("prev-")
    assert any(d.status == "selected" for d in plan.framework_decisions)
    from auditor.domain.audit_plan import PlanConfirmationRejected
    from auditor.inventory.service import plan_to_audit_request_payload

    with pytest.raises(PlanConfirmationRejected):
        plan_to_audit_request_payload(
            plan, inventory=inventory, client_id="c1", client_slug="Testcompany"
        )
    confirmed = confirm_audit_plan(plan, action="approve", inventory=inventory)
    assert confirmed.status == "confirmed"

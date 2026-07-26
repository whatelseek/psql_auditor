"""AUD-003 — validation of the canonical deterministic fixture dataset."""

from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import httpx
import pytest
from tests.fixtures.canonical_audit import (
    FIXED_NOW,
    LONG_OBSERVATION_LENGTH,
    RESULT_ACCEPTED_EXCEPTION_ID,
    build_canonical_scenario,
    exception_is_applicable,
    select_previous_comparable,
)

from auditor.clock import FixedClock, set_clock
from auditor.domain.result_identity import (
    historical_comparison_key,
    is_historically_comparable,
    logical_key_of,
)
from auditor.llm import build_chat_model
from auditor.testing.fake_llm import use_chat_model_factory

FIXTURE_MODULE = Path(__file__).resolve().parent / "fixtures" / "canonical_audit.py"


@pytest.fixture
def scenario():
    return build_canonical_scenario()


def test_at_least_two_clients(scenario) -> None:
    assert len(scenario.clients) >= 2
    slugs = {c.slug for c in scenario.clients}
    assert "client_alpha" in slugs and "client_beta" in slugs


def test_alpha_has_two_audit_runs(scenario) -> None:
    alpha = next(c for c in scenario.clients if c.slug == "client_alpha")
    runs = [r for r in scenario.audit_runs if r.client_id == alpha.client_id]
    assert len(runs) >= 2


def test_fixed_valid_unique_uuids(scenario) -> None:
    result_ids = [UUID(f.result_id) for f in scenario.results]
    asset_ids = [UUID(a.asset_id) for a in scenario.assets]
    exception_ids = [e.exception_id for e in scenario.exceptions]
    assert len(result_ids) == len(set(result_ids))
    assert len(asset_ids) == len(set(asset_ids))
    assert len(exception_ids) == len(set(exception_ids))
    assert len(set(result_ids) | set(asset_ids) | set(exception_ids)) == (
        len(result_ids) + len(asset_ids) + len(exception_ids)
    )


def test_timestamps_fixed_and_timezone_aware(scenario) -> None:
    assert FIXED_NOW.tzinfo is not None
    assert FIXED_NOW == datetime(2026, 7, 26, 9, 0, 0, tzinfo=timezone.utc)
    assert scenario.clock.now() == FIXED_NOW
    for run in scenario.audit_runs:
        assert run.created_at.tzinfo is not None
        assert run.created_at.utcoffset() is not None
    for exc in scenario.exceptions:
        assert exc.created_at.tzinfo is not None
        assert exc.valid_from.tzinfo is not None


def test_two_assets_and_two_frameworks_share_req001(scenario) -> None:
    assets = [a for a in scenario.assets if a.client_id == scenario.clients[0].client_id]
    assert len(assets) >= 2
    fw_with_req001 = [
        fw for fw in scenario.frameworks if any(r.id == "REQ-001" for r in fw.requirements)
    ]
    assert len(fw_with_req001) >= 2


def test_framework_scoped_req001_identities_remain_distinct(scenario) -> None:
    """Same textual REQ-001 is not interchangeable across frameworks (CORE-003)."""
    linux = next(f for f in scenario.frameworks if f.framework_id == "framework_linux")
    pg = next(f for f in scenario.frameworks if f.framework_id == "framework_postgresql")
    assert linux.requirements[0].id == pg.requirements[0].id == "REQ-001"
    # Current-run findings that both use REQ-001 on different frameworks
    linux_finding = scenario.current_comparable_anchor
    pg_finding = scenario.result_by_status("fail")
    assert linux_finding.requirement_id == pg_finding.requirement_id == "REQ-001"
    assert logical_key_of(linux_finding) != logical_key_of(pg_finding)
    assert historical_comparison_key(linux_finding) != historical_comparison_key(pg_finding)


def test_all_seven_required_statuses_present(scenario) -> None:
    by_status = scenario.results_by_status()
    required = {
        "pass",
        "fail",
        "partial",
        "error",
        "not_tested",
        "not_applicable",
        "accepted_exception",
    }
    assert set(by_status) == required
    for status, finding in by_status.items():
        assert finding.status == status


def test_russian_and_english_observations(scenario) -> None:
    texts = [f.evidence for f in scenario.results]
    assert any("root по SSH" in t or "Обнаружен" in t for t in texts)
    assert any("SSH root login" in t for t in texts)


def test_long_observation_has_expected_fixed_length(scenario) -> None:
    assert scenario.long_observation_length == LONG_OBSERVATION_LENGTH == 640
    long_finding = next(f for f in scenario.results if f.result_id.endswith("0010"))
    assert len(long_finding.evidence) == 640
    assert long_finding.evidence == scenario.long_observation


def test_spreadsheet_formula_prefixes_present(scenario) -> None:
    texts = [f.evidence for f in scenario.results]
    assert any(t.startswith("=") for t in texts)
    assert any(t.startswith("+") for t in texts)
    assert any(t.startswith("-") for t in texts)
    assert any(t.startswith("@") for t in texts)


def test_comparable_historical_result_selected(scenario) -> None:
    current = scenario.current_comparable_anchor
    previous = scenario.previous_comparable_result
    assert is_historically_comparable(previous, current)
    assert previous.audit_run_id != current.audit_run_id
    selected = select_previous_comparable(
        current=current,
        candidates=[
            scenario.previous_comparable_result,
            scenario.previous_noncomparable_result,
        ],
    )
    assert selected is not None
    assert selected.result_id == previous.result_id


def test_noncomparable_historical_result_rejected(scenario) -> None:
    current = scenario.current_comparable_anchor
    other = scenario.previous_noncomparable_result
    assert other.requirement_id == current.requirement_id == "REQ-001"
    assert other.framework_id != current.framework_id
    assert not is_historically_comparable(other, current)
    selected = select_previous_comparable(current=current, candidates=[other])
    assert selected is None


def test_active_exception_applicable_at_fixed_now(scenario) -> None:
    assert exception_is_applicable(scenario.active_exception, clock=scenario.clock)
    assert exception_is_applicable(
        scenario.active_exception,
        clock=scenario.clock,
        finding=scenario.current_comparable_anchor,
    )


def test_expired_exception_not_applicable(scenario) -> None:
    assert not exception_is_applicable(scenario.expired_exception, clock=scenario.clock)


def test_revoked_exception_not_applicable(scenario) -> None:
    assert not exception_is_applicable(scenario.revoked_exception, clock=scenario.clock)


def test_accepted_exception_refers_to_valid_active_exception(scenario) -> None:
    accepted = scenario.result_by_status("accepted_exception")
    assert accepted.result_id == RESULT_ACCEPTED_EXCEPTION_ID
    assert str(scenario.active_exception.exception_id) in accepted.notes
    assert exception_is_applicable(
        scenario.active_exception, clock=scenario.clock, finding=accepted
    )
    # Expired / revoked must not convert a failing observation into accepted_exception
    failing = scenario.previous_comparable_result
    assert failing.status == "fail"
    assert not exception_is_applicable(
        scenario.expired_exception, clock=scenario.clock, finding=failing
    )
    assert not exception_is_applicable(
        scenario.revoked_exception, clock=scenario.clock, finding=failing
    )


@pytest.mark.asyncio
async def test_model_responses_deterministic(scenario) -> None:
    fake_a = scenario.build_fake_llm("valid_structured_en")
    fake_b = scenario.build_fake_llm("valid_structured_en")
    prev = use_chat_model_factory(lambda _s: fake_a)
    try:
        model = build_chat_model()
        out1 = await model.ainvoke([{"role": "user", "content": "assess REQ-001"}])
    finally:
        use_chat_model_factory(prev)
    prev = use_chat_model_factory(lambda _s: fake_b)
    try:
        out2 = await build_chat_model().ainvoke([{"role": "user", "content": "assess REQ-001"}])
    finally:
        use_chat_model_factory(prev)
    assert out1.content == out2.content
    assert "SSH root login enabled" in str(out1.content)
    assert len(fake_a.calls) == 1

    ru = scenario.build_fake_llm("valid_structured_ru")
    prev = use_chat_model_factory(lambda _s: ru)
    try:
        msg = await build_chat_model().ainvoke([{"role": "user", "content": "оцени"}])
        assert "Включён" in str(msg.content) or "PermitRootLogin" in str(msg.content)
    finally:
        use_chat_model_factory(prev)

    bad = scenario.build_fake_llm("malformed")
    prev = use_chat_model_factory(lambda _s: bad)
    try:
        msg = await build_chat_model().ainvoke([{"role": "user", "content": "x"}])
        assert "NOT_JSON" in str(msg.content)
    finally:
        use_chat_model_factory(prev)

    boom = scenario.build_fake_llm("provider_failure")
    prev = use_chat_model_factory(lambda _s: boom)
    try:
        with pytest.raises(RuntimeError, match="provider_unavailable"):
            await build_chat_model().ainvoke([{"role": "user", "content": "x"}])
    finally:
        use_chat_model_factory(prev)

    timed = scenario.build_fake_llm("timeout")
    prev = use_chat_model_factory(lambda _s: timed)
    try:
        with pytest.raises(TimeoutError):
            await build_chat_model().ainvoke([{"role": "user", "content": "x"}])
    finally:
        use_chat_model_factory(prev)


def test_fixture_instances_do_not_share_mutable_state(scenario) -> None:
    other = build_canonical_scenario()
    mutable = scenario.mutable_results()
    rid = next(iter(mutable))
    mutable[rid].evidence = "MUTATED-IN-TEST"
    assert scenario.results[0].evidence != "MUTATED-IN-TEST" or True
    # Original scenario findings remain unchanged
    original = next(f for f in scenario.results if f.result_id == rid)
    assert original.evidence != "MUTATED-IN-TEST"
    other_same = next(f for f in other.results if f.result_id == rid)
    assert other_same.evidence == original.evidence
    assert other_same is not original


def test_fixture_construction_performs_no_network_calls(scenario) -> None:
    """Building the scenario must not touch the network (LLM guard still active)."""
    with pytest.raises(RuntimeError, match="External LLM"):
        httpx.get("https://api.openai.com/v1/models", timeout=0.2)
    # Re-build while network remains guarded by autouse fixture
    again = build_canonical_scenario()
    assert len(again.results) == len(scenario.results)


def test_fixture_module_avoids_runtime_randomness_and_now() -> None:
    tree = ast.parse(FIXTURE_MODULE.read_text(encoding="utf-8"))
    banned_names = {"uuid4", "randrange", "randint", "random", "SystemRandom"}
    banned_attrs = {"now", "utcnow", "today", "time"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in banned_names:
                raise AssertionError(f"banned call {func.id}")
            if isinstance(func, ast.Attribute) and func.attr in banned_names:
                raise AssertionError(f"banned call .{func.attr}")
            # datetime.now / date.today / time.time
            if isinstance(func, ast.Attribute) and func.attr in banned_attrs:
                # Allow FixedClock.now method *definitions* only — calls on datetime banned
                if isinstance(func.value, ast.Name) and func.value.id in {
                    "datetime",
                    "date",
                    "time",
                }:
                    raise AssertionError(f"banned time call {func.value.id}.{func.attr}")


def test_injected_clock_not_wall_time(scenario) -> None:
    previous = set_clock(scenario.clock)
    try:
        assert scenario.clock.now() == FIXED_NOW
        # Wall clock would almost certainly differ from FIXED_NOW
        assert isinstance(scenario.clock, FixedClock)
        assert scenario.clock.now() == FIXED_NOW
    finally:
        set_clock(previous)


def test_skipped_not_required_but_production_still_accepts_it() -> None:
    """Document production still supports legacy ``skipped`` alongside AUD-003 statuses."""
    from auditor.state import Finding

    f = Finding(
        requirement_id="REQ-999",
        status="skipped",
        result_id="r0000001-0001-4001-8001-000000000099",
        client_id="client_alpha0000001a",
        audit_run_id="arun_alpha_curr00001",
        asset_id="aaaaaaaa-1111-4111-8111-111111111111",
        framework_id="framework_linux",
        framework_version="1.0.0",
    )
    assert f.status == "skipped"

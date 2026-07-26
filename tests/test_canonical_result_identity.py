"""CORE-003: Canonical result identity (result_id + full logical key)."""

from __future__ import annotations

from pathlib import Path

import pytest

from auditor.asset_registry import get_asset_registry
from auditor.domain import (
    DuplicateLogicalKeyError,
    DuplicateResultIdError,
    IncompleteResultIdentityError,
    merge_result_maps,
    new_result_id,
    validate_result_identity,
)
from auditor.frameworks import get_framework
from auditor.result_identity_bind import attach_result_identity
from auditor.result_store import ResultStore
from auditor.state import Finding, merge_findings, render_report


def _finding(
    *,
    result_id: str,
    client_id: str = "acme",
    audit_run_id: str = "arun_1",
    asset_id: str = "asset_a",
    framework_id: str = "fw_a",
    framework_version: str = "1.0",
    requirement_id: str = "REQ-001",
    status: str = "pass",
) -> Finding:
    return Finding(
        result_id=result_id,
        client_id=client_id,
        audit_run_id=audit_run_id,
        asset_id=asset_id,
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_id=requirement_id,
        status=status,  # type: ignore[arg-type]
        title=requirement_id,
    )


def test_two_assets_two_frameworks_four_results():
    """Two assets × two frameworks × REQ-001 → four distinct results."""
    store = ResultStore()
    ids = []
    for asset in ("asset_1", "asset_2"):
        for fw in ("fw_a", "fw_b"):
            rid = new_result_id()
            ids.append(rid)
            store.put(
                _finding(
                    result_id=rid,
                    asset_id=asset,
                    framework_id=fw,
                    requirement_id="REQ-001",
                )
            )
    assert len(store) == 4
    assert len(set(ids)) == 4
    reqs = {f.requirement_id for f in store.all()}
    assert reqs == {"REQ-001"}
    assets = {f.asset_id for f in store.all()}
    assert assets == {"asset_1", "asset_2"}


def test_worker_completion_order_does_not_change_identities():
    """Changing merge order must not change the resulting identity set."""
    a = _finding(result_id="11111111-1111-1111-1111-111111111111", asset_id="a")
    b = _finding(
        result_id="22222222-2222-2222-2222-222222222222",
        asset_id="b",
        framework_id="fw_b",
    )
    first = merge_findings({a.result_id: a}, {b.result_id: b})
    second = merge_findings({b.result_id: b}, {a.result_id: a})
    assert set(first) == set(second) == {a.result_id, b.result_id}
    assert {f.asset_id for f in first.values()} == {f.asset_id for f in second.values()}


def test_duplicate_result_id_raises():
    store = ResultStore()
    rid = new_result_id()
    store.put(_finding(result_id=rid, asset_id="a"))
    with pytest.raises(DuplicateResultIdError):
        store.put(
            _finding(result_id=rid, asset_id="b", framework_id="other"),
            allow_update=True,
        )


def test_duplicate_logical_key_lists_conflicting_key():
    store = ResultStore()
    store.put(_finding(result_id=new_result_id(), asset_id="a"))
    with pytest.raises(DuplicateLogicalKeyError) as excinfo:
        store.put(_finding(result_id=new_result_id(), asset_id="a"))
    msg = str(excinfo.value)
    assert "client_id=" in msg
    assert "audit_run_id=" in msg
    assert "asset_id=" in msg
    assert "framework_id=" in msg
    assert "framework_version=" in msg
    assert "requirement_id=" in msg
    assert "REQ-001" in msg


def test_same_requirement_different_framework_versions_ok():
    store = ResultStore()
    store.put(
        _finding(
            result_id=new_result_id(),
            framework_id="ubuntu_cis",
            framework_version="24.0",
            requirement_id="REQ-001",
        )
    )
    store.put(
        _finding(
            result_id=new_result_id(),
            framework_id="ubuntu_cis",
            framework_version="22.0",
            requirement_id="REQ-001",
        )
    )
    assert len(store) == 2


def test_asset_id_stable_across_runs_when_ip_changes(tmp_path: Path):
    registry = get_asset_registry(tmp_path)
    aid1 = registry.ensure_asset(
        client_id="acme",
        inventory_key="db-primary",
        label="db-primary",
        ssh_host="10.0.0.1",
    )
    aid2 = registry.ensure_asset(
        client_id="acme",
        inventory_key="db-primary",
        label="db-primary",
        ssh_host="10.0.0.99",
    )
    assert aid1 == aid2
    row = registry.get_asset(aid1)
    assert row is not None
    assert row["ssh_host"] == "10.0.0.99"


def test_assessment_validation_report_preserve_result_id():
    """Assessment → external validation → report keep the same result_id."""
    rid = new_result_id()
    assessed = _finding(result_id=rid, status="fail")
    # External validation corrects status but keeps identity.
    validated = assessed.model_copy(update={"status": "pass", "notes": "validated"})
    assert validated.result_id == rid
    assert logical_unchanged(assessed, validated)

    merged = merge_findings({rid: assessed}, {rid: validated})
    assert merged[rid].result_id == rid
    assert merged[rid].status == "pass"

    report = render_report(
        "Demo",
        merged,
        requirements=None,
    )
    assert "REQ-001" in report
    assert validated.result_id == rid


def logical_unchanged(a: Finding, b: Finding) -> bool:
    return (
        a.result_id == b.result_id
        and a.client_id == b.client_id
        and a.audit_run_id == b.audit_run_id
        and a.asset_id == b.asset_id
        and a.framework_id == b.framework_id
        and a.framework_version == b.framework_version
        and a.requirement_id == b.requirement_id
    )


def test_framework_version_mandatory_for_persist():
    f = Finding(requirement_id="REQ-001", status="pass", result_id=new_result_id())
    with pytest.raises(IncompleteResultIdentityError):
        validate_result_identity(f, for_persist=True)


def test_attach_reuses_existing_result_id():
    existing = {
        "result_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "client_id": "acme",
        "audit_run_id": "arun_x",
        "asset_id": "asset_1",
        "framework_id": "postgres_cis",
        "framework_version": "1.0",
        "requirement_id": "REQ-001",
        "status": "fail",
    }
    finding = Finding(requirement_id="REQ-001", status="pass")
    attach_result_identity(
        finding,
        state={
            "client_id": "acme",
            "audit_run_id": "arun_x",
            "asset_id": "asset_1",
            "framework_version": "1.0",
        },
        framework_id="postgres_cis",
        framework_version="1.0",
        existing=existing,
    )
    assert finding.result_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_agents_declare_framework_version():
    fw = get_framework("postgres_cis", Path("agents"))
    assert fw is not None
    assert fw.version
    fw2 = get_framework("ubuntu_cis_24_l2", Path("agents"))
    assert fw2 is not None
    assert fw2.version


def test_merge_result_maps_rejects_logical_collision():
    a = _finding(result_id=new_result_id())
    b = _finding(result_id=new_result_id())
    with pytest.raises(DuplicateLogicalKeyError):
        merge_result_maps({a.result_id: a}, {b.result_id: b})

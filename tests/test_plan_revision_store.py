"""INPUT005-08 — immutable plan revision store + concurrency-safe latest pointer."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from auditor.domain.audit_plan import AuditPlan, AuditPlanSummary
from auditor.domain.inventory import (
    ClientInventory,
    InventoryHost,
    InventoryVersion,
)
from auditor.inventory.plan_store import (
    POINTER_SCHEMA_VERSION,
    PlanRevisionStore,
    PlanStoreError,
    _atomic_write_text,
)
from auditor.inventory.service import (
    analyze_client_inventory,
    astart_confirmed_audit,
    confirm_audit_plan,
    load_effective_inventory_revision,
)


def _inventory(*, client_id: str = "c1", host_note: str = "a") -> ClientInventory:
    return ClientInventory(
        client_id=client_id,
        version=InventoryVersion(
            version_id="inv-1",
            content_hash=f"hash-{host_note}",
            source_path=f"{client_id}/INVENTORY.md",
            source_format="markdown",
            recorded_at="2026-01-01T00:00:00Z",
        ),
        hosts=(
            InventoryHost(
                host_id="host-01",
                address="10.0.0.1",
                os_family="linux",
                connection_types=("ssh",),
            ),
        ),
    )


def _plan(
    *,
    plan_id: str = "plan-abc",
    plan_revision_id: str = "prev-old",
    note: str = "",
    status: str = "draft",
) -> AuditPlan:
    return AuditPlan(
        plan_id=plan_id,
        plan_revision_id=plan_revision_id,
        client_id="c1",
        inventory_version_id="inv-1",
        inventory_content_hash="hash-a",
        status=status,  # type: ignore[arg-type]
        summary=AuditPlanSummary(
            total_hosts=1,
            total_audit_target_instances=0,
        ),
        created_at="2026-01-01T00:00:00Z",
        confirmation_note=note,
    )


def test_multiple_revisions_retained(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    inv_old = _inventory(host_note="old")
    inv_new = _inventory(host_note="new")
    old = _plan(plan_revision_id="prev-old")
    new = _plan(plan_revision_id="prev-new")

    store.persist_revision(old, inv_old, make_latest=True)
    store.persist_revision(new, inv_new, make_latest=True)

    old_path = store.revision_plan_path("prev-old")
    new_path = store.revision_plan_path("prev-new")
    assert old_path.is_file()
    assert new_path.is_file()
    assert store.load_revision("prev-old").plan.plan_revision_id == "prev-old"
    assert store.load_revision("prev-new").plan.plan_revision_id == "prev-new"
    assert store.current_revision_id() == "prev-new"


def test_effective_inventories_are_revision_specific(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    inv_old = _inventory(host_note="old")
    inv_new = _inventory(host_note="new")
    store.persist_revision(_plan(plan_revision_id="prev-old"), inv_old, make_latest=True)
    store.persist_revision(_plan(plan_revision_id="prev-new"), inv_new, make_latest=True)

    loaded_old = store.load_revision("prev-old").effective_inventory
    loaded_new = store.load_revision("prev-new").effective_inventory
    assert loaded_old.version.content_hash != loaded_new.version.content_hash
    assert loaded_old.version.content_hash == "hash-old"
    # Old immutable file untouched after newer persist.
    raw_old = store.revision_inventory_path("prev-old").read_text(encoding="utf-8")
    assert "hash-old" in raw_old
    assert "hash-new" not in raw_old


def test_idempotent_write(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    plan = _plan(plan_revision_id="prev-same")
    inv = _inventory()
    first = store.persist_revision(plan, inv, make_latest=True)
    second = store.persist_revision(plan, inv, make_latest=True)
    assert first.plan_path == second.plan_path
    assert first.inventory_path == second.inventory_path
    assert first.plan_path.read_bytes() == second.plan_path.read_bytes()


def test_revision_collision(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    plan = _plan(plan_revision_id="prev-collide", note="a")
    inv = _inventory()
    store.persist_revision(plan, inv, make_latest=True)
    original = store.revision_plan_path("prev-collide").read_bytes()
    with pytest.raises(PlanStoreError, match="collision") as exc:
        store.persist_revision(
            _plan(plan_revision_id="prev-collide", note="different"),
            inv,
            make_latest=True,
        )
    assert exc.value.code == "plan_revision_collision"
    assert store.revision_plan_path("prev-collide").read_bytes() == original


def test_atomic_latest_update_rolls_back_on_replace_failure(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    old = _plan(plan_revision_id="prev-old")
    inv = _inventory(host_note="old")
    store.persist_revision(old, inv, make_latest=True)
    old_pointer = store.pointer_path.read_text(encoding="utf-8")
    old_latest = store.latest_plan_path.read_text(encoding="utf-8")

    real_replace = __import__("os").replace

    def _boom(src: str | Path, dst: str | Path) -> None:
        dst_path = Path(dst)
        if dst_path.name == "latest.pointer.json":
            raise RuntimeError("simulated replace failure")
        return real_replace(src, dst)

    with patch("auditor.inventory.plan_store.os.replace", side_effect=_boom):
        with pytest.raises(RuntimeError, match="simulated"):
            store.persist_revision(
                _plan(plan_revision_id="prev-new"),
                _inventory(host_note="new"),
                make_latest=True,
            )

    assert store.pointer_path.read_text(encoding="utf-8") == old_pointer
    assert store.latest_plan_path.read_text(encoding="utf-8") == old_latest
    # No partial JSON / leftover temps for pointer destination.
    leftovers = list(store.root.glob(".latest.pointer.json.*.tmp"))
    assert leftovers == []
    json.loads(old_pointer)
    json.loads(old_latest)


def test_stale_concurrent_confirmation(tmp_path: Path):
    """Locked compare/write path rejects an older confirmation after a newer analyze."""
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    old = _plan(plan_revision_id="prev-old")
    new = _plan(plan_revision_id="prev-new")
    store.persist_revision(old, _inventory(host_note="old"), make_latest=True)

    # Process A loads the old revision while it is current.
    loaded_old = store.load_revision("prev-old")
    assert loaded_old.plan.plan_revision_id == "prev-old"

    # Process B advances latest under the store lock.
    store.persist_revision(new, _inventory(host_note="new"), make_latest=True)

    # Process A attempts to claim/confirm the stale revision under the lock.
    with pytest.raises(PlanStoreError) as exc:
        store.assert_current("prev-old")
    assert exc.value.code == "audit_plan_stale"

    with pytest.raises(PlanStoreError) as exc2:
        store.persist_latest_materialized_plan(
            loaded_old.plan.model_copy(update={"status": "confirmed"}),
            expected_plan_revision_id="prev-old",
        )
    assert exc2.value.code == "audit_plan_stale"

    pointer = json.loads(store.pointer_path.read_text(encoding="utf-8"))
    assert pointer["plan_revision_id"] == "prev-new"
    latest = json.loads(store.latest_plan_path.read_text(encoding="utf-8"))
    assert latest["plan_revision_id"] == "prev-new"
    immutable_old = json.loads(store.revision_plan_path("prev-old").read_text(encoding="utf-8"))
    assert immutable_old["status"] == "draft"

    # Concurrent lock contention: holder blocks updater until release.
    hold = threading.Event()
    released = threading.Event()
    errors: list[BaseException] = []

    def _holder() -> None:
        try:
            with store._exclusive_lock():
                hold.set()
                released.wait(timeout=2.0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def _waiter() -> None:
        hold.wait(timeout=2.0)
        try:
            store.assert_current("prev-new")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            released.set()

    t1 = threading.Thread(target=_holder)
    t2 = threading.Thread(target=_waiter)
    t1.start()
    t2.start()
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)
    assert errors == []


def test_current_revision_confirm_leaves_immutable_bytes(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    plan = _plan(plan_revision_id="prev-cur")
    inv = _inventory()
    store.persist_revision(plan, inv, make_latest=True)
    before = store.revision_plan_path("prev-cur").read_bytes()

    confirmed = plan.model_copy(
        update={"status": "confirmed", "confirmed_at": "2026-01-01T00:00:01Z"}
    )
    store.persist_latest_materialized_plan(
        confirmed,
        expected_plan_revision_id="prev-cur",
    )
    latest = json.loads(store.latest_plan_path.read_text(encoding="utf-8"))
    assert latest["status"] == "confirmed"
    assert store.revision_plan_path("prev-cur").read_bytes() == before


def test_invalid_pointer_cases(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    store.persist_revision(_plan(), _inventory(), make_latest=True)

    def _write_pointer(payload: object) -> None:
        store.pointer_path.write_text(
            json.dumps(payload) if not isinstance(payload, str) else payload,
            encoding="utf-8",
        )

    cases = [
        "{not-json",
        {
            "schema_version": "nope",
            "plan_id": "p",
            "plan_revision_id": "prev-old",
            "plan_path": "revisions/prev-old/plan.json",
            "effective_inventory_path": "revisions/prev-old/effective.inventory.json",
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "p",
            "plan_revision_id": "prev-old",
            "plan_path": "/abs/revisions/prev-old/plan.json",
            "effective_inventory_path": "revisions/prev-old/effective.inventory.json",
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "p",
            "plan_revision_id": "prev-old",
            "plan_path": "../revisions/prev-old/plan.json",
            "effective_inventory_path": "revisions/prev-old/effective.inventory.json",
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "p",
            "plan_revision_id": "prev-old",
            "plan_path": "revisions/prev-other/plan.json",
            "effective_inventory_path": "revisions/prev-old/effective.inventory.json",
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "wrong-plan",
            "plan_revision_id": "prev-old",
            "plan_path": "revisions/prev-old/plan.json",
            "effective_inventory_path": "revisions/prev-old/effective.inventory.json",
        },
    ]
    for payload in cases:
        _write_pointer(payload)
        with pytest.raises(PlanStoreError) as exc:
            store.load_latest()
        assert exc.value.code == "invalid_plan_pointer"


@pytest.mark.asyncio
async def test_start_uses_revision_specific_inventory(tmp_path: Path):
    """Confirmed revision keeps its inventory even after a newer global effective."""
    from auditor.config import Settings

    root = tmp_path / "inventory"
    client = root / "RevInv"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        """# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.40.1 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.40.1 | 22 | audit | CANARY_PW_STORE |
""",
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    settings = Settings(
        _env_file=None,
        evidence_dir=evidence,
        inventory_dir=root,
        agents_dir=Path("agents"),
        intake_enabled=False,
        hitl_enabled=False,
        archive_enabled=False,
    )

    from tests.test_input005_discovery import _linux_transport

    from auditor.inventory.collectors import (
        DiscoveryHostSettings,
        SshDiscoveryCollector,
    )

    with patch("auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"):
        with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
            with patch("auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"):
                inv_old, plan_old = analyze_client_inventory(
                    root,
                    "RevInv",
                    agents_dir=Path("agents"),
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="RevInv",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(),
                    ),
                )
                confirmed = confirm_audit_plan(
                    plan_old,
                    action="approve",
                    inventory=inv_old,
                    inventory_dir=root,
                    client_name="RevInv",
                    expected_plan_revision_id=plan_old.plan_revision_id,
                )
                plans_store = PlanRevisionStore(root / "RevInv" / ".audit_plans")
                plans_store.persist_latest_materialized_plan(
                    confirmed,
                    expected_plan_revision_id=plan_old.plan_revision_id,
                )

                inv_new, plan_new = analyze_client_inventory(
                    root,
                    "RevInv",
                    agents_dir=Path("agents"),
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="RevInv",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(with_postgres=True),
                    ),
                )

    assert plan_new.plan_id == plan_old.plan_id
    assert plan_new.plan_revision_id != plan_old.plan_revision_id
    assert inv_new.version.content_hash == inv_old.version.content_hash

    old_eff = load_effective_inventory_revision(root, "RevInv", plan_old.plan_revision_id)
    new_eff = load_effective_inventory_revision(root, "RevInv", plan_new.plan_revision_id)
    old_pg = any(s.name == "postgresql" for h in old_eff.hosts for s in h.services)
    new_pg = any(s.name == "postgresql" for h in new_eff.hosts for s in h.services)
    assert not old_pg
    assert new_pg

    captured: dict[str, object] = {}

    async def _executor(request):
        captured["version_id"] = request.inventory.version_id
        captured["content_hash"] = request.inventory.content_hash
        return {"audit_run_id": "run_rev", "audit_run_status": "running"}

    started = await astart_confirmed_audit(
        root,
        "RevInv",
        confirmed,
        settings=settings,
        agents_dir=Path("agents"),
        executor=_executor,
        expected_plan_revision_id=plan_old.plan_revision_id,
    )
    assert started["audit_run_id"] == "run_rev"
    assert captured["version_id"] == old_eff.version.version_id
    assert captured["content_hash"] == old_eff.version.content_hash
    # Global compatibility file points at the newer analyze.
    global_eff = json.loads(
        (root / "RevInv" / ".audit_plans" / "effective.inventory.json").read_text(encoding="utf-8")
    )
    assert global_eff["version"]["content_hash"] == inv_new.version.content_hash


def test_atomic_write_helper_removes_temp_on_failure(tmp_path: Path):
    target = tmp_path / "out.json"
    target.write_text('{"ok": true}\n', encoding="utf-8")

    def _boom_write(*_a, **_k):
        raise OSError("disk full")

    with patch("auditor.inventory.plan_store.os.fdopen", side_effect=_boom_write):
        with pytest.raises(OSError):
            _atomic_write_text(target, '{"new": true}\n')
    assert target.read_text(encoding="utf-8") == '{"ok": true}\n'
    assert list(tmp_path.glob(".out.json.*.tmp")) == []

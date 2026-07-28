"""INPUT005-08 — immutable plan revision store hardening."""

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
    find_client_for_plan_revision,
    validate_plan_revision_id,
)
from auditor.inventory.service import (
    analyze_client_inventory,
    astart_confirmed_audit,
    confirm_audit_plan,
    load_effective_inventory_revision,
)


def _inventory(
    *,
    client_id: str = "c1",
    host_note: str = "a",
    recorded_at: str = "2026-01-01T00:00:00Z",
    marker: str = "",
) -> ClientInventory:
    notes = marker or host_note
    return ClientInventory(
        client_id=client_id,
        version=InventoryVersion(
            version_id="inv-1",
            content_hash=f"hash-{host_note}",
            source_path=f"{client_id}/INVENTORY.md",
            source_format="markdown",
            recorded_at=recorded_at,
        ),
        hosts=(
            InventoryHost(
                host_id="host-01",
                address="10.0.0.1",
                os_family="linux",
                connection_types=("ssh",),
                notes=notes,
            ),
        ),
    )


def _plan(
    *,
    plan_id: str = "plan-abc",
    plan_revision_id: str = "prev-1234567890abcdef",
    note: str = "",
    status: str = "draft",
    created_at: str = "2026-01-01T00:00:00Z",
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
        created_at=created_at,
        confirmation_note=note,
    )


def test_multiple_revisions_retained(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    inv_old = _inventory(host_note="old")
    inv_new = _inventory(host_note="new")
    old = _plan(plan_revision_id="prev-1111111111111111")
    new = _plan(plan_revision_id="prev-2222222222222222")

    store.persist_revision(old, inv_old, make_latest=True)
    store.persist_revision(new, inv_new, make_latest=True)

    assert store.revision_plan_path("prev-1111111111111111").is_file()
    assert store.revision_plan_path("prev-2222222222222222").is_file()
    assert store.load_revision("prev-1111111111111111").plan.plan_revision_id == (
        "prev-1111111111111111"
    )
    assert store.current_revision_id() == "prev-2222222222222222"


def test_effective_inventories_are_revision_specific(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    store.persist_revision(
        _plan(plan_revision_id="prev-1111111111111111"),
        _inventory(host_note="old"),
        make_latest=True,
    )
    store.persist_revision(
        _plan(plan_revision_id="prev-2222222222222222"),
        _inventory(host_note="new"),
        make_latest=True,
    )
    loaded_old = store.load_revision("prev-1111111111111111").effective_inventory
    loaded_new = store.load_revision("prev-2222222222222222").effective_inventory
    assert loaded_old.version.content_hash != loaded_new.version.content_hash
    raw_old = store.revision_inventory_path("prev-1111111111111111").read_text(encoding="utf-8")
    assert "hash-old" in raw_old
    assert "hash-new" not in raw_old


def test_identical_analysis_different_timestamps_is_idempotent(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    rev = "prev-aaaaaaaaaaaaaaaa"
    first_plan = _plan(plan_revision_id=rev, created_at="2026-01-01T00:00:00Z")
    second_plan = _plan(plan_revision_id=rev, created_at="2026-01-02T00:00:00Z")
    first_inv = _inventory(recorded_at="2026-01-01T00:00:00Z")
    second_inv = _inventory(recorded_at="2026-01-02T00:00:00Z")

    first = store.persist_revision(first_plan, first_inv, make_latest=True)
    before_plan = first.plan_path.read_bytes()
    before_inv = first.inventory_path.read_bytes()
    second = store.persist_revision(second_plan, second_inv, make_latest=True)

    assert first.plan.plan_revision_id == second.plan.plan_revision_id == rev
    assert list(store.revisions_dir.iterdir()) == [store.revision_dir(rev)]
    assert second.plan_path.read_bytes() == before_plan
    assert second.inventory_path.read_bytes() == before_inv
    assert second.plan.created_at == "2026-01-01T00:00:00Z"
    assert second.effective_inventory.version.recorded_at == "2026-01-01T00:00:00Z"


def test_divergent_semantic_collision(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    rev = "prev-bbbbbbbbbbbbbbbb"
    plan = _plan(plan_revision_id=rev, note="a")
    inv = _inventory()
    store.persist_revision(plan, inv, make_latest=True)
    original_plan = store.revision_plan_path(rev).read_bytes()
    original_inv = store.revision_inventory_path(rev).read_bytes()

    with pytest.raises(PlanStoreError) as exc:
        store.persist_revision(
            _plan(plan_revision_id=rev, note="different"),
            inv,
            make_latest=True,
        )
    assert exc.value.code == "plan_revision_collision"
    assert store.revision_plan_path(rev).read_bytes() == original_plan
    assert store.revision_inventory_path(rev).read_bytes() == original_inv


def test_idempotent_byte_identical_write(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    plan = _plan(plan_revision_id="prev-cccccccccccccccc")
    inv = _inventory()
    first = store.persist_revision(plan, inv, make_latest=True)
    second = store.persist_revision(plan, inv, make_latest=True)
    assert first.plan_path == second.plan_path
    assert first.plan_path.read_bytes() == second.plan_path.read_bytes()


def test_concurrent_identical_writers(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    rev = "prev-dddddddddddddddd"
    results: list[object] = []
    errors: list[BaseException] = []

    def _writer(created_at: str, recorded_at: str) -> None:
        try:
            snap = store.persist_revision(
                _plan(plan_revision_id=rev, created_at=created_at),
                _inventory(recorded_at=recorded_at),
                make_latest=True,
            )
            results.append(snap)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=_writer, args=("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))
    t2 = threading.Thread(target=_writer, args=("2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z"))
    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert errors == []
    assert len(results) == 2
    dirs = [p for p in store.revisions_dir.iterdir() if p.is_dir()]
    assert len(dirs) == 1
    assert not list(store.revisions_dir.glob(".*.tmp"))
    loaded = store.load_revision(rev)
    assert loaded.plan.plan_revision_id == rev
    assert loaded.effective_inventory.version.version_id == "inv-1"


def test_concurrent_divergent_writers(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    rev = "prev-eeeeeeeeeeeeeeee"
    successes: list[str] = []
    collisions: list[str] = []
    lock = threading.Lock()

    def _writer(marker: str) -> None:
        try:
            store.persist_revision(
                _plan(
                    plan_revision_id=rev,
                    note=marker,
                    created_at=f"2026-01-0{marker[-1]}T00:00:00Z",
                ),
                _inventory(marker=marker, recorded_at=f"2026-01-0{marker[-1]}T00:00:00Z"),
                make_latest=True,
            )
            with lock:
                successes.append(marker)
        except PlanStoreError as exc:
            assert exc.code == "plan_revision_collision"
            with lock:
                collisions.append(marker)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                collisions.append(f"unexpected:{exc}")

    t1 = threading.Thread(target=_writer, args=("A1",))
    t2 = threading.Thread(target=_writer, args=("B2",))
    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert len(successes) == 1
    assert len(collisions) == 1
    winner = successes[0]
    loaded = store.load_revision(rev)
    assert loaded.plan.confirmation_note == winner
    assert loaded.effective_inventory.hosts[0].notes == winner
    assert store.revision_plan_path(rev).read_bytes()
    # Loser bytes never present.
    loser = collisions[0]
    assert loser != winner
    assert loser not in store.revision_plan_path(rev).read_text(encoding="utf-8")
    assert loser not in store.revision_inventory_path(rev).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "fail_name",
    ["latest.json", "effective.inventory.json", "latest.pointer.json"],
)
def test_compatibility_publication_failure_rolls_back(tmp_path: Path, fail_name: str):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    old = _plan(plan_revision_id="prev-1111111111111111")
    store.persist_revision(old, _inventory(host_note="old"), make_latest=True)
    prev_pointer = store.pointer_path.read_bytes()
    prev_latest = store.latest_plan_path.read_bytes()
    prev_inv = store.latest_inventory_path.read_bytes()

    real_replace = __import__("os").replace
    calls = {"n": 0}

    def _boom(src: str | Path, dst: str | Path) -> None:
        dst_path = Path(dst)
        if dst_path.name == fail_name:
            calls["n"] += 1
            raise RuntimeError(f"simulated {fail_name} failure")
        return real_replace(src, dst)

    with patch("auditor.inventory.plan_store.os.replace", side_effect=_boom):
        with pytest.raises(RuntimeError, match="simulated"):
            store.persist_revision(
                _plan(plan_revision_id="prev-2222222222222222"),
                _inventory(host_note="new"),
                make_latest=True,
            )

    assert calls["n"] == 1
    assert store.pointer_path.read_bytes() == prev_pointer
    assert store.latest_plan_path.read_bytes() == prev_latest
    assert store.latest_inventory_path.read_bytes() == prev_inv
    assert store.load_latest().plan.plan_revision_id == "prev-1111111111111111"
    assert list(store.root.glob(".*.tmp")) == []


def test_lock_open_failure(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    real_open = open

    def _open(path, *args, **kwargs):  # noqa: ANN001
        if Path(path) == store.lock_path:
            raise PermissionError("denied")
        return real_open(path, *args, **kwargs)

    with patch("builtins.open", side_effect=_open):
        with pytest.raises(PlanStoreError) as exc:
            store.persist_revision(_plan(), _inventory(), make_latest=True)
    assert exc.value.code == "plan_store_lock_failed"


def test_root_mkdir_failure(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    real_mkdir = Path.mkdir

    def _mkdir(self: Path, *args, **kwargs):  # noqa: ANN001
        if self == store.root:
            raise PermissionError("denied")
        return real_mkdir(self, *args, **kwargs)

    with patch.object(Path, "mkdir", _mkdir):
        with pytest.raises(PlanStoreError) as exc:
            store.persist_revision(_plan(), _inventory(), make_latest=True)
    assert exc.value.code == "plan_store_lock_failed"


@pytest.mark.parametrize(
    "bad_id",
    [
        "../prev-1234567890abcdef",
        "../../client",
        "/absolute/path",
        "prev-ABCDEF1234567890",
        "prev-123",
        "prev-1234567890abcdef/other",
    ],
)
def test_revision_traversal_rejected(tmp_path: Path, bad_id: str):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    store.persist_revision(_plan(), _inventory(), make_latest=True)
    revisions_root = store.revisions_dir.resolve()

    with pytest.raises(PlanStoreError) as exc_load:
        store.load_revision(bad_id)
    assert exc_load.value.code == "plan_revision_not_found"

    with pytest.raises(PlanStoreError) as exc_dir:
        store.revision_dir(bad_id)
    assert exc_dir.value.code == "plan_revision_not_found"

    with pytest.raises(PlanStoreError) as exc_assert:
        store.assert_current(bad_id)
    assert exc_assert.value.code == "plan_revision_not_found"

    with pytest.raises(PlanStoreError) as exc_find:
        find_client_for_plan_revision(
            tmp_path,
            plan_id="plan-abc",
            plan_revision_id=bad_id,
        )
    assert exc_find.value.code == "plan_revision_not_found"

    # No escape: revisions dir contents remain under revisions/.
    for path in store.revisions_dir.rglob("*"):
        assert revisions_root in path.resolve().parents or path.resolve() == revisions_root


def test_invalid_pointer_cases(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    store.persist_revision(_plan(), _inventory(), make_latest=True)

    def _write_pointer(payload: object) -> None:
        store.pointer_path.write_text(
            json.dumps(payload) if not isinstance(payload, str) else payload,
            encoding="utf-8",
        )

    cases: list[object] = [
        "{not-json",
        {
            "schema_version": "nope",
            "plan_id": "p",
            "plan_revision_id": "prev-1234567890abcdef",
            "plan_path": "revisions/prev-1234567890abcdef/plan.json",
            "effective_inventory_path": (
                "revisions/prev-1234567890abcdef/effective.inventory.json"
            ),
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "p",
            "plan_revision_id": "prev-1234567890abcdef",
            "plan_path": "/abs/revisions/prev-1234567890abcdef/plan.json",
            "effective_inventory_path": (
                "revisions/prev-1234567890abcdef/effective.inventory.json"
            ),
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "p",
            "plan_revision_id": "prev-1234567890abcdef",
            "plan_path": "../revisions/prev-1234567890abcdef/plan.json",
            "effective_inventory_path": (
                "revisions/prev-1234567890abcdef/effective.inventory.json"
            ),
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "p",
            "plan_revision_id": "prev-1234567890abcdef",
            "plan_path": "revisions/prev-otherother0000/plan.json",
            "effective_inventory_path": (
                "revisions/prev-1234567890abcdef/effective.inventory.json"
            ),
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "wrong-plan",
            "plan_revision_id": "prev-1234567890abcdef",
            "plan_path": "revisions/prev-1234567890abcdef/plan.json",
            "effective_inventory_path": (
                "revisions/prev-1234567890abcdef/effective.inventory.json"
            ),
        },
        {
            "schema_version": POINTER_SCHEMA_VERSION,
            "plan_id": "p",
            "plan_revision_id": "../prev-1234567890abcdef",
            "plan_path": "revisions/../prev-1234567890abcdef/plan.json",
            "effective_inventory_path": (
                "revisions/../prev-1234567890abcdef/effective.inventory.json"
            ),
        },
    ]
    for payload in cases:
        _write_pointer(payload)
        with pytest.raises(PlanStoreError) as exc:
            store.load_latest()
        assert exc.value.code == "invalid_plan_pointer"


def test_stale_concurrent_confirmation(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    old = _plan(plan_revision_id="prev-1111111111111111")
    new = _plan(plan_revision_id="prev-2222222222222222")
    store.persist_revision(old, _inventory(host_note="old"), make_latest=True)
    loaded_old = store.load_revision("prev-1111111111111111")
    store.persist_revision(new, _inventory(host_note="new"), make_latest=True)

    with pytest.raises(PlanStoreError) as exc:
        store.assert_current("prev-1111111111111111")
    assert exc.value.code == "audit_plan_stale"
    with pytest.raises(PlanStoreError) as exc2:
        store.persist_latest_materialized_plan(
            loaded_old.plan.model_copy(update={"status": "confirmed"}),
            expected_plan_revision_id="prev-1111111111111111",
        )
    assert exc2.value.code == "audit_plan_stale"
    assert (
        json.loads(store.pointer_path.read_text(encoding="utf-8"))["plan_revision_id"]
        == "prev-2222222222222222"
    )


def test_current_revision_confirm_leaves_immutable_bytes(tmp_path: Path):
    store = PlanRevisionStore(tmp_path / ".audit_plans")
    plan = _plan(plan_revision_id="prev-ffffffffffffffff")
    store.persist_revision(plan, _inventory(), make_latest=True)
    before = store.revision_plan_path("prev-ffffffffffffffff").read_bytes()
    confirmed = plan.model_copy(
        update={"status": "confirmed", "confirmed_at": "2026-01-01T00:00:01Z"}
    )
    store.persist_latest_materialized_plan(
        confirmed,
        expected_plan_revision_id="prev-ffffffffffffffff",
    )
    latest = json.loads(store.latest_plan_path.read_text(encoding="utf-8"))
    assert latest["status"] == "confirmed"
    assert store.revision_plan_path("prev-ffffffffffffffff").read_bytes() == before


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


def test_validate_plan_revision_id_accepts_canonical():
    assert validate_plan_revision_id("prev-1234567890abcdef") == "prev-1234567890abcdef"


@pytest.mark.asyncio
async def test_start_uses_revision_specific_inventory(tmp_path: Path):
    """Confirmed revision keeps its inventory even after a newer global effective."""
    from tests.test_input005_discovery import _linux_transport

    from auditor.config import Settings
    from auditor.inventory.collectors import (
        DiscoveryHostSettings,
        SshDiscoveryCollector,
    )

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
    assert not any(s.name == "postgresql" for h in old_eff.hosts for s in h.services)
    assert any(s.name == "postgresql" for h in new_eff.hosts for s in h.services)

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

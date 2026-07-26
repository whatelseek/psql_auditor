"""Inventory-driven audit launch (INPUT-003 / INPUT-005 / workflow gate)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from auditor.domain.audit_plan import PlanConfirmationRejected
from auditor.inventory.client_name import InvalidClientNameError, validate_client_name
from auditor.inventory.loaders import InventoryLoadError
from auditor.inventory.service import (
    analyze_client_inventory,
    confirm_audit_plan,
    load_client_inventory,
    plan_to_audit_request_payload,
    reject_audit_launch,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "inventory"
AGENTS = Path("agents")
CANARY = "CANARY_PW_INV_UNIQUE_9c2e"


def _copy_client(tmp_path: Path, *, name: str = "Testcompany", fmt: str = "md") -> Path:
    src = FIXTURES / "Testcompany"
    dest_root = tmp_path / "inventory"
    dest = dest_root / name
    dest.mkdir(parents=True)
    if fmt == "md":
        shutil.copy(src / "INVENTORY.md", dest / "INVENTORY.md")
    elif fmt == "yaml":
        shutil.copy(src / "INVENTORY.yaml", dest / "INVENTORY.yaml")
    elif fmt == "json":
        shutil.copy(src / "INVENTORY.json", dest / "INVENTORY.json")
    else:
        raise AssertionError(fmt)
    return dest_root


def test_invalid_client_name_rejected():
    with pytest.raises(InvalidClientNameError):
        validate_client_name("Test Company")
    with pytest.raises(InvalidClientNameError):
        validate_client_name("Testcompany!")
    assert validate_client_name("Testcompany") == "Testcompany"
    assert validate_client_name("Test_company_01") == "Test_company_01"


def test_missing_inventory_file(tmp_path: Path):
    root = tmp_path / "inventory"
    (root / "Testcompany").mkdir(parents=True)
    with pytest.raises(InventoryLoadError, match="missing inventory"):
        load_client_inventory(root, "Testcompany")


def test_valid_markdown_inventory_five_hosts(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    inventory = load_client_inventory(root, "Testcompany")
    assert inventory.client_id == "Testcompany"
    assert len(inventory.hosts) == 5
    assert inventory.version.content_hash
    assert inventory.version.version_id.startswith("inv-")
    assert sum(1 for h in inventory.hosts if h.os_family == "linux") == 4
    assert sum(1 for h in inventory.hosts if h.os_family == "windows") == 1
    assert sum(1 for h in inventory.hosts if any(s.name == "postgresql" for s in h.services)) == 2
    # Secrets are references only — canary plaintext must not appear in dump.
    dumped = json.dumps(inventory.model_dump())
    assert "changeme" not in dumped
    assert CANARY not in dumped


def test_valid_yaml_and_json_inventory(tmp_path: Path):
    for fmt in ("yaml", "json"):
        root = _copy_client(tmp_path / fmt, fmt=fmt)
        inventory = load_client_inventory(root, "Testcompany")
        assert len(inventory.hosts) == 5
        assert inventory.version.source_format in {"yaml", "json"}


def test_duplicate_hosts_detected(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "DupClient"
    client.mkdir(parents=True)
    (client / "INVENTORY.yaml").write_text(
        yaml.safe_dump(
            {
                "client": "DupClient",
                "hosts": [
                    {"id": "host-01", "os": "Ubuntu", "address": "10.0.0.1", "services": ["ssh"]},
                    {"id": "host-01", "os": "Ubuntu", "address": "10.0.0.2", "services": ["ssh"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    inventory = load_client_inventory(root, "DupClient")
    assert any(i.code == "duplicate_host" and i.level == "error" for i in inventory.issues)


def test_missing_host_address_warning(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "NoAddr"
    client.mkdir(parents=True)
    (client / "INVENTORY.yaml").write_text(
        yaml.safe_dump(
            {
                "client": "NoAddr",
                "hosts": [{"id": "host-01", "os": "Ubuntu", "services": ["ssh"]}],
            }
        ),
        encoding="utf-8",
    )
    inventory = load_client_inventory(root, "NoAddr")
    assert any(i.code == "missing_address" and i.level == "warning" for i in inventory.issues)


def test_contradictory_service_information(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "BadSvc"
    client.mkdir(parents=True)
    (client / "INVENTORY.yaml").write_text(
        yaml.safe_dump(
            {
                "client": "BadSvc",
                "hosts": [
                    {
                        "id": "host-01",
                        "os": "Ubuntu",
                        "address": "10.0.0.1",
                        "services": ["ssh", "winrm"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    inventory = load_client_inventory(root, "BadSvc")
    assert any(i.code == "contradictory_service" for i in inventory.issues)
    # Host-level error must not invent a project-wide empty inventory.
    assert len(inventory.hosts) == 1
    assert inventory.hosts_without_errors() == []


def test_automatic_framework_selection_and_plan(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    inventory, plan = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS)
    assert plan.status == "draft"
    assert plan.requires_confirmation()
    assert plan.summary.total_hosts == 5
    assert plan.summary.linux_hosts == 4
    assert plan.summary.windows_hosts == 1
    assert plan.summary.postgresql_instances == 2
    # 4 ubuntu + 1 windows + 2 postgres + 1 general infra = 8 target instances
    assert plan.summary.total_audit_target_instances == 8
    selected = [d for d in plan.framework_decisions if d.status == "selected"]
    selected_ids = {d.framework_id for d in selected}
    assert "ubuntu_cis_24_l2" in selected_ids
    assert "postgres_cis" in selected_ids
    assert "windows_server" in selected_ids
    assert "host_facts" in selected_ids
    # Physical hosts are not duplicated.
    host_ids = {t.host_id for t in plan.targets if not t.target_id.startswith("client:")}
    assert host_ids == {"host-01", "host-02", "host-03", "host-04", "host-05"}
    assert inventory.version.version_id == plan.inventory_version_id


def test_plan_confirmation_required_and_rejection(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="yaml")
    _inventory, plan = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS)
    with pytest.raises(PlanConfirmationRejected, match="not confirmed"):
        reject_audit_launch(plan)
    with pytest.raises(PlanConfirmationRejected):
        plan_to_audit_request_payload(plan)

    rejected = confirm_audit_plan(plan, action="reject", note="operator declined")
    assert rejected.status == "rejected"
    with pytest.raises(PlanConfirmationRejected):
        reject_audit_launch(rejected)

    confirmed = confirm_audit_plan(plan, action="approve", note="ok")
    assert confirmed.status == "confirmed"
    assert confirmed.is_executable()
    payload = plan_to_audit_request_payload(confirmed)
    assert payload["schema_version"] == 1
    assert payload["client_id"] == "Testcompany"
    assert payload["targets"]
    blob = json.dumps(payload)
    assert CANARY not in blob
    # AuditRequest must remain secret-free (no credential material).
    for forbidden in ("password", "secret_ref", "vault://", "ssh_password"):
        assert forbidden not in blob.lower()


def test_exclude_host_before_confirm(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="json")
    _inventory, plan = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS)
    trimmed = confirm_audit_plan(plan, action="exclude_host", host_ids=["host-05"])
    assert trimmed.status == "draft"
    assert all(t.excluded for t in trimmed.targets if t.host_id == "host-05")
    confirmed = confirm_audit_plan(trimmed, action="approve")
    assert confirmed.status == "confirmed"
    assert all(t.host_id != "host-05" for t in confirmed.active_targets)


def test_secret_redaction_in_normalized_model(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "SecClient"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        f"""# Inventory

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.1 | 22 | audit | {CANARY} | |

## In-scope hosts

| Host | Operating System | Discovered Services | IP |
|---|---|---|---|
| host-01 | Ubuntu | SSH | 10.0.0.1 |
""",
        encoding="utf-8",
    )
    inventory = load_client_inventory(root, "SecClient")
    dumped = json.dumps(inventory.model_dump())
    assert CANARY not in dumped
    assert inventory.credentials
    assert inventory.credentials[0].has_secret is True
    assert inventory.credentials[0].secret_ref == ""


def test_inventory_version_changes_when_hosts_change(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="yaml")
    first = load_client_inventory(root, "Testcompany")
    path = root / "Testcompany" / "INVENTORY.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["hosts"].append(
        {
            "id": "host-06",
            "os": "Ubuntu",
            "address": "10.200.29.76",
            "services": ["ssh"],
        }
    )
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    second = load_client_inventory(root, "Testcompany")
    assert first.version.content_hash != second.version.content_hash
    assert first.version.version_id != second.version.version_id
    assert len(second.hosts) == 6


def test_plan_generation_idempotent(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    _i1, p1 = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS)
    _i2, p2 = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS)
    assert p1.plan_id == p2.plan_id
    assert p1.inventory_content_hash == p2.inventory_content_hash


def test_plan_json_roundtrip(tmp_path: Path):
    from auditor.inventory.plan import load_plan, persist_plan

    root = _copy_client(tmp_path, fmt="md")
    _inventory, plan = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS)
    path = tmp_path / "plan.json"
    persist_plan(plan, path)
    loaded = load_plan(path)
    assert loaded.plan_id == plan.plan_id
    assert loaded.summary.total_hosts == 5
    assert len(loaded.targets) == len(plan.targets)
    confirmed = confirm_audit_plan(loaded, action="approve")
    assert confirmed.is_executable()

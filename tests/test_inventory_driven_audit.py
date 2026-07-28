"""Inventory-driven audit launch (INPUT-003 / INPUT-005 / workflow gate)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import yaml

from auditor.api.app import create_app
from auditor.application_runtime import ApplicationRuntime
from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry
from auditor.config import Settings
from auditor.domain.audit_models import new_audit_run_id
from auditor.domain.audit_plan import PlanConfirmationRejected
from auditor.domain.audit_request import (
    AuditRequestRejected,
    parse_audit_request,
    validate_audit_request_semantics,
)
from auditor.graph import AuditorGraph
from auditor.inventory.client_name import InvalidClientNameError, validate_client_name
from auditor.inventory.discovery import DiscoveredHostFacts, StaticDiscoveryCollector
from auditor.inventory.loaders import InventoryLoadError
from auditor.inventory.plan import persist_plan
from auditor.inventory.service import (
    analyze_client_inventory,
    astart_confirmed_audit,
    confirm_audit_plan,
    load_client_inventory,
    plan_to_audit_request_payload,
    reject_audit_launch,
    start_confirmed_audit,
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


def _payload(plan, inventory, *, client_id: str = "client_test", slug: str = "testcompany"):
    return plan_to_audit_request_payload(
        plan,
        inventory=inventory,
        client_id=client_id,
        client_slug=slug,
    )


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
    assert len(inventory.hosts) == 1
    assert inventory.hosts_without_errors() == []


def test_automatic_framework_selection_and_plan(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    assert plan.status == "draft"
    assert plan.requires_confirmation()
    assert plan.summary.total_hosts == 5
    assert plan.summary.linux_hosts == 4
    assert plan.summary.windows_hosts == 1
    assert plan.summary.postgresql_instances == 2
    assert plan.summary.total_audit_target_instances == 12
    selected = [d for d in plan.framework_decisions if d.status == "selected"]
    selected_ids = {d.framework_id for d in selected}
    assert "ubuntu_cis_24_l2" in selected_ids
    assert "postgres_cis" in selected_ids
    assert "windows_server" in selected_ids
    assert "host_facts" in selected_ids
    host_ids = {t.host_id for t in plan.targets if not t.target_id.startswith("client:")}
    assert host_ids == {"host-01", "host-02", "host-03", "host-04", "host-05"}
    assert sum(1 for t in plan.targets if t.framework_id == "host_facts") == 5
    assert inventory.version.version_id == plan.inventory_version_id
    assert plan.plan_revision_id.startswith("prev-")


def test_plan_confirmation_required_and_rejection(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    with pytest.raises(PlanConfirmationRejected, match="not confirmed"):
        reject_audit_launch(plan)
    with pytest.raises(PlanConfirmationRejected):
        _payload(plan, inventory)

    rejected = confirm_audit_plan(plan, action="reject", note="operator declined")
    assert rejected.status == "rejected"
    with pytest.raises(PlanConfirmationRejected):
        reject_audit_launch(rejected)

    confirmed = confirm_audit_plan(plan, action="approve", note="ok", inventory=inventory)
    assert confirmed.status == "confirmed"
    assert confirmed.is_executable()
    payload = _payload(confirmed, inventory, slug="Testcompany")
    assert payload["schema_version"] == 1
    assert payload["inventory"]["version_id"] == inventory.version.version_id
    assert payload["inventory"]["content_hash"] == inventory.version.content_hash
    assert payload["targets"]
    blob = json.dumps(payload)
    assert CANARY not in blob
    for forbidden in ("password", "secret_ref", "vault://", "ssh_password"):
        assert forbidden not in blob.lower()


def test_exclude_host_before_confirm(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    trimmed = confirm_audit_plan(plan, action="exclude_host", host_ids=["host-05"])
    assert trimmed.status == "draft"
    assert all(t.excluded for t in trimmed.targets if t.host_id == "host-05")
    confirmed = confirm_audit_plan(trimmed, action="approve", inventory=inventory)
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
    _i1, p1 = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS, discovery=False)
    _i2, p2 = analyze_client_inventory(root, "Testcompany", agents_dir=AGENTS, discovery=False)
    assert p1.plan_id == p2.plan_id
    assert p1.inventory_content_hash == p2.inventory_content_hash


def test_plan_json_roundtrip(tmp_path: Path):
    from auditor.inventory.plan import load_plan, persist_plan

    root = _copy_client(tmp_path, fmt="md")
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    path = tmp_path / "plan.json"
    persist_plan(plan, path)
    loaded = load_plan(path)
    assert loaded.plan_id == plan.plan_id
    confirmed = confirm_audit_plan(loaded, action="approve", inventory=inventory)
    assert confirmed.is_executable()


def test_stale_plan_rejected_after_inventory_modification(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    _inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    path = root / "Testcompany" / "INVENTORY.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("host-05", "host-05b"), encoding="utf-8")
    with pytest.raises(PlanConfirmationRejected) as exc:
        confirm_audit_plan(
            plan,
            action="approve",
            inventory_dir=root,
            client_name="Testcompany",
        )
    assert exc.value.code in {"plan_stale", "audit_plan_stale"}


def test_unchanged_plan_accepted(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    confirmed = confirm_audit_plan(
        plan,
        action="approve",
        inventory_dir=root,
        client_name="Testcompany",
    )
    assert confirmed.status == "confirmed"
    assert confirmed.inventory_content_hash == inventory.version.content_hash


def test_credentials_loaded_from_separate_credentials_md(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "CredClient"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        """# Inventory

## In-scope hosts

| Host | Operating System | Discovered Services | IP | Access |
|---|---|---|---|---|
| host-01 | Ubuntu | SSH | 10.0.0.9 | SSH |
""",
        encoding="utf-8",
    )
    (client / "CREDENTIALS.md").write_text(
        f"""# Credentials

| Access | Host / URL | Port | Username | Password / Token | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.9 | 22 | audit_user | {CANARY} | |
| PostgreSQL | 10.0.0.9 | 5432 | auditor_ro | vault://client/pg/host01 | appdb |
""",
        encoding="utf-8",
    )
    inventory = load_client_inventory(root, "CredClient")
    assert len(inventory.credentials) == 2
    assert {c.access for c in inventory.credentials} == {"ssh", "postgresql"}
    assert any(c.target_host_id == "host-01" for c in inventory.credentials)
    dumped = json.dumps(inventory.model_dump())
    assert CANARY not in dumped
    assert "vault://client/pg/host01" in dumped


def test_plaintext_absent_from_plan_and_request(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "SecPlan"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        f"""# Inventory

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.8 | 22 | audit | {CANARY} | |

## In-scope hosts

| Host | OS | Services | IP |
|---|---|---|---|
| host-01 | Ubuntu | SSH | 10.0.0.8 |
""",
        encoding="utf-8",
    )
    inventory, plan = analyze_client_inventory(root, "SecPlan", agents_dir=AGENTS, discovery=False)
    confirmed = confirm_audit_plan(plan, action="approve", inventory=inventory)
    payload = _payload(confirmed, inventory, slug="SecPlan")
    for blob in (
        json.dumps(inventory.model_dump()),
        json.dumps(plan.model_dump()),
        json.dumps(confirmed.model_dump()),
        json.dumps(payload),
    ):
        assert CANARY not in blob


def test_inventory_ip_port_credentials_without_os_needs_discovery(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "NeedsDisc"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        """# Inventory

## In-scope hosts

| Host | IP | Access | Port |
|---|---|---|---:|
| host-01 | 10.0.0.11 | SSH | 22 |
""",
        encoding="utf-8",
    )
    (client / "CREDENTIALS.md").write_text(
        """# Credentials

| Access | Host / URL | Port | Username | Secret Reference | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.11 | 22 | audit_user | vault://x/ssh | |
""",
        encoding="utf-8",
    )
    inventory = load_client_inventory(root, "NeedsDisc")
    assert any(i.code == "needs_discovery" for i in inventory.issues)
    assert not any(i.code == "missing_os" and i.level == "error" for i in inventory.issues)
    assert inventory.hosts_without_errors()
    assert inventory.hosts[0].os_family == ""


def test_ssh_discovery_selects_linux_and_postgresql(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "DiscLinux"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        """# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.21 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Secret Reference | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.21 | 22 | audit | vault://x | |
""",
        encoding="utf-8",
    )
    discoverer = StaticDiscoveryCollector(
        [
            DiscoveredHostFacts(
                host_id="host-01",
                os_name="Ubuntu 24.04",
                os_family="linux",
                hostname="db-01",
                services=["ssh", "postgresql"],
                listening_ports=[22, 5432],
                evidence_ref="ssh:host-01/os-release",
            )
        ]
    )
    inventory, plan = analyze_client_inventory(
        root, "DiscLinux", agents_dir=AGENTS, discoverer=discoverer
    )
    assert inventory.hosts[0].os_family == "linux"
    assert any(
        s.name == "postgresql" and s.source == "discovered" for s in inventory.hosts[0].services
    )
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "ubuntu_cis_24_l2" in selected
    assert "postgres_cis" in selected
    assert any(f.source == "discovered" for f in inventory.hosts[0].facts)


def test_winrm_discovery_selects_windows(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "DiscWin"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        """# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.31 | WinRM |

## Credentials & Access

| Access | Host / URL | Port | Username | Secret Reference | Database |
|---|---|---:|---|---|---|
| WinRM | 10.0.0.31 | 5985 | audit | vault://x | |
""",
        encoding="utf-8",
    )
    discoverer = StaticDiscoveryCollector(
        [
            DiscoveredHostFacts(
                host_id="host-01",
                os_name="Windows Server 2022",
                os_family="windows",
                hostname="win-01",
                services=["winrm"],
                listening_ports=[5985],
                evidence_ref="winrm:host-01/os",
            )
        ]
    )
    _inventory, plan = analyze_client_inventory(
        root, "DiscWin", agents_dir=AGENTS, discoverer=discoverer
    )
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "windows_server" in selected


def test_inventory_discovery_conflict_requests_clarification(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Conflict"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        """# Inventory

## In-scope hosts

| Host | OS | IP | Access |
|---|---|---|---|
| host-01 | Ubuntu | 10.0.0.41 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Secret Reference | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.41 | 22 | audit | vault://x | |
""",
        encoding="utf-8",
    )
    discoverer = StaticDiscoveryCollector(
        [
            DiscoveredHostFacts(
                host_id="host-01",
                os_name="Windows Server 2019",
                os_family="windows",
                hostname="win-conflict",
                services=["winrm"],
                evidence_ref="ssh:conflict",
            )
        ]
    )
    inventory, plan = analyze_client_inventory(
        root, "Conflict", agents_dir=AGENTS, discoverer=discoverer
    )
    assert inventory.conflicts
    assert any(i.code == "fact_conflict" for i in inventory.issues)
    assert any("Clarify conflict" in q for q in plan.unresolved_questions)
    selected_os = [
        d for d in plan.framework_decisions if d.target_id == "host-01" and d.status == "selected"
    ]
    assert selected_os == []


def test_weak_port_only_evidence_does_not_select_postgresql(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "WeakPg"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        """# Inventory

## In-scope hosts

| Host | OS | IP | Access |
|---|---|---|---|
| host-01 | Ubuntu | 10.0.0.51 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Secret Reference | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.51 | 22 | audit | vault://x | |
""",
        encoding="utf-8",
    )
    discoverer = StaticDiscoveryCollector(
        [
            DiscoveredHostFacts(
                host_id="host-01",
                os_name="Ubuntu",
                os_family="linux",
                services=["ssh"],
                listening_ports=[5432],
                evidence_ref="ssh:ports",
            )
        ]
    )
    _inventory, plan = analyze_client_inventory(
        root, "WeakPg", agents_dir=AGENTS, discoverer=discoverer
    )
    pg_decisions = [d for d in plan.framework_decisions if "postgres" in d.framework_id]
    assert pg_decisions
    assert all(d.status == "requires_operator_decision" for d in pg_decisions)
    assert not any(t.framework_id == "postgres_cis" and not t.excluded for t in plan.targets)


def test_confirmed_start_creates_real_audit_run(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    settings = Settings(
        _env_file=None,
        evidence_dir=evidence,
        inventory_dir=root,
        agents_dir=AGENTS,
        intake_enabled=False,
        hitl_enabled=False,
        archive_enabled=False,
        max_parallel_assessments=5,
        max_parallel_host_jobs=2,
    )
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )

    async def _executor(request):
        client = get_client_registry(evidence).get(request.client_id)
        assert client is not None
        run_id = new_audit_run_id()
        get_audit_registry(evidence).create_run(
            client_id=request.client_id,
            audit_run_id=run_id,
        )
        return {
            "audit_run_id": run_id,
            "evidence_run_id": "ev_test",
            "audit_run_status": "running",
            "awaiting_hitl": False,
            "thread_id": "t1",
        }

    started = start_confirmed_audit(
        root,
        "Testcompany",
        plan,
        settings=settings,
        agents_dir=AGENTS,
        note="ok",
        executor=_executor,
    )
    assert started["audit_run_id"]
    assert started["audit_request"]["inventory"]["content_hash"] == inventory.version.content_hash
    assert started["audit_request"]["inventory"]["version_id"] == inventory.version.version_id
    stored = get_audit_registry(evidence).get_run(started["audit_run_id"])
    assert stored is not None
    assert stored.client_id == started["client_id"]
    blob = json.dumps(started["audit_request"])
    assert CANARY not in blob
    assert "vault://" not in blob


def _settings_for(tmp_path: Path, root: Path) -> Settings:
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    return Settings(
        _env_file=None,
        evidence_dir=evidence,
        inventory_dir=root,
        agents_dir=AGENTS,
        intake_enabled=False,
        hitl_enabled=False,
        archive_enabled=False,
        max_parallel_assessments=5,
        max_parallel_host_jobs=2,
    )


class _FakeGraph:
    """Minimal graph stand-in for API start tests."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def arun_request(self, request, operator_context: str = "") -> dict:
        run_id = new_audit_run_id()
        get_audit_registry(self.settings.evidence_dir).create_run(
            client_id=request.client_id,
            audit_run_id=run_id,
        )
        return {
            "audit_run_id": run_id,
            "evidence_run_id": "ev_api",
            "audit_run_status": "running",
            "awaiting_hitl": False,
            "thread_id": "t-api",
        }

    async def aclose_runtime_resources(self, timeout: float | None = None) -> None:
        return None


@pytest.mark.asyncio
async def test_api_start_true_works_in_active_event_loop(tmp_path: Path):
    """API start=true must await astart (no asyncio.run) inside FastAPI loop."""
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    plans = root / "Testcompany" / ".audit_plans"
    plans.mkdir(parents=True, exist_ok=True)
    persist_plan(plan, plans / "latest.json")

    async def _runtime_factory():
        runtime = ApplicationRuntime(
            settings,
            graph_factory=lambda rt: _FakeGraph(rt.settings),  # type: ignore[arg-type, return-value]
            shutdown_timeout=0.5,
        )
        await runtime.start()
        return runtime

    app = create_app(settings=settings, runtime_factory=_runtime_factory)

    with patch(
        "auditor.inventory.service.asyncio.run",
        side_effect=AssertionError("asyncio.run must not be called from API start"),
    ):
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    f"/audit-plans/{plan.plan_id}/confirm",
                    json={"action": "approve", "start": True, "note": "api-start"},
                )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["audit_run_id"]
    assert body["audit_request"]["inventory"]["version_id"] == inventory.version.version_id
    assert body["audit_request"]["inventory"]["content_hash"] == inventory.version.content_hash
    assert get_audit_registry(settings.evidence_dir).get_run(body["audit_run_id"]) is not None
    blob = json.dumps(body)
    assert CANARY not in blob
    assert "vault://" not in blob


@pytest.mark.asyncio
async def test_astart_confirmed_audit_direct_async(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    _inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )

    async def _executor(request):
        run_id = new_audit_run_id()
        get_audit_registry(settings.evidence_dir).create_run(
            client_id=request.client_id,
            audit_run_id=run_id,
        )
        return {"audit_run_id": run_id, "audit_run_status": "running"}

    with patch(
        "auditor.inventory.service.asyncio.run",
        side_effect=AssertionError("asyncio.run must not be called from astart"),
    ):
        started = await astart_confirmed_audit(
            root,
            "Testcompany",
            plan,
            settings=settings,
            agents_dir=AGENTS,
            note="async",
            executor=_executor,
        )
    assert started["audit_run_id"]


def test_cli_sync_start_still_works(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    _inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )

    async def _executor(request):
        run_id = new_audit_run_id()
        get_audit_registry(settings.evidence_dir).create_run(
            client_id=request.client_id,
            audit_run_id=run_id,
        )
        return {"audit_run_id": run_id, "audit_run_status": "running"}

    started = start_confirmed_audit(
        root,
        "Testcompany",
        plan,
        settings=settings,
        agents_dir=AGENTS,
        note="cli",
        executor=_executor,
    )
    assert started["audit_run_id"]
    assert started["status"] == "started"


def test_unchanged_inventory_request_passes_semantic_validation(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    confirmed = confirm_audit_plan(plan, action="approve", note="ok", inventory=inventory)
    client = get_client_registry(settings.evidence_dir).ensure_client(
        display_name="Testcompany", slug="Testcompany"
    )
    payload = plan_to_audit_request_payload(
        confirmed,
        inventory=inventory,
        client_id=client.client_id,
        client_slug=client.slug,
    )
    validated = validate_audit_request_semantics(parse_audit_request(payload), settings)
    assert validated.inventory.version_id == inventory.version.version_id
    assert validated.inventory.content_hash == inventory.version.content_hash


def test_changed_inventory_rejects_inventory_hash_mismatch(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    confirmed = confirm_audit_plan(plan, action="approve", note="ok", inventory=inventory)
    client = get_client_registry(settings.evidence_dir).ensure_client(
        display_name="Testcompany", slug="Testcompany"
    )
    payload = plan_to_audit_request_payload(
        confirmed,
        inventory=inventory,
        client_id=client.client_id,
        client_slug=client.slug,
    )
    # Keep pinned version_id but force a wrong content_hash.
    payload["inventory"]["content_hash"] = "0" * 64
    with pytest.raises(AuditRequestRejected) as exc:
        validate_audit_request_semantics(parse_audit_request(payload), settings)
    assert any(i.code == "inventory_hash_mismatch" for i in exc.value.issues)
    detail = exc.value.operator_message()
    assert CANARY not in detail
    assert "vault://" not in detail


def test_changed_version_rejects_inventory_version_mismatch(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    confirmed = confirm_audit_plan(plan, action="approve", note="ok", inventory=inventory)
    client = get_client_registry(settings.evidence_dir).ensure_client(
        display_name="Testcompany", slug="Testcompany"
    )
    payload = plan_to_audit_request_payload(
        confirmed,
        inventory=inventory,
        client_id=client.client_id,
        client_slug=client.slug,
    )
    # Hash matches current inventory; version_id alone is stale/wrong.
    payload["inventory"]["version_id"] = "inv-deadbeef0000"
    with pytest.raises(AuditRequestRejected) as exc:
        validate_audit_request_semantics(parse_audit_request(payload), settings)
    assert any(i.code == "inventory_version_mismatch" for i in exc.value.issues)
    assert CANARY not in exc.value.operator_message()


@pytest.mark.asyncio
async def test_saved_request_cannot_execute_after_inventory_modification(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    confirmed = confirm_audit_plan(plan, action="approve", note="ok", inventory=inventory)
    client = get_client_registry(settings.evidence_dir).ensure_client(
        display_name="Testcompany", slug="Testcompany"
    )
    payload = plan_to_audit_request_payload(
        confirmed,
        inventory=inventory,
        client_id=client.client_id,
        client_slug=client.slug,
    )
    saved = root / "Testcompany" / ".audit_plans" / "audit_request.json"
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Modify normalized inventory identity after the request was saved
    # (host address change alters ClientInventory.version content_hash).
    inv_path = root / "Testcompany" / "INVENTORY.md"
    text = inv_path.read_text(encoding="utf-8")
    inv_path.write_text(
        text.replace("10.200.29.71", "10.200.29.171"),
        encoding="utf-8",
    )
    mutated = load_client_inventory(root, "Testcompany")
    assert mutated.version.content_hash != inventory.version.content_hash

    replay = parse_audit_request(json.loads(saved.read_text(encoding="utf-8")))
    with pytest.raises(AuditRequestRejected) as exc:
        validate_audit_request_semantics(replay, settings)
    assert any(
        i.code in {"inventory_hash_mismatch", "inventory_version_mismatch"}
        for i in exc.value.issues
    )

    graph = AuditorGraph(settings=settings)

    async def _must_not_run(*_a, **_k):
        raise AssertionError("jobs must not start for stale inventory request")

    with patch.object(AuditorGraph, "_run_framework_jobs", _must_not_run):
        with pytest.raises(AuditRequestRejected) as exc2:
            await graph.arun_request(replay, operator_context="replay stale request")
    assert any(
        i.code in {"inventory_hash_mismatch", "inventory_version_mismatch"}
        for i in exc2.value.issues
    )
    err = json.dumps(exc2.value.to_dict())
    assert CANARY not in err
    assert "vault://" not in err


def test_identity_rejection_errors_do_not_expose_secrets(tmp_path: Path):
    root = _copy_client(tmp_path, fmt="md")
    settings = _settings_for(tmp_path, root)
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    confirmed = confirm_audit_plan(plan, action="approve", note="ok", inventory=inventory)
    client = get_client_registry(settings.evidence_dir).ensure_client(
        display_name="Testcompany", slug="Testcompany"
    )
    payload = plan_to_audit_request_payload(
        confirmed,
        inventory=inventory,
        client_id=client.client_id,
        client_slug=client.slug,
    )
    payload["inventory"]["content_hash"] = "f" * 64
    with pytest.raises(AuditRequestRejected) as exc:
        validate_audit_request_semantics(parse_audit_request(payload), settings)
    blob = json.dumps(exc.value.to_dict()) + exc.value.operator_message()
    assert CANARY not in blob
    assert "vault://" not in blob
    assert "changeme" not in blob
    for issue in exc.value.issues:
        assert "password" not in issue.message.lower() or "content_hash" in issue.location

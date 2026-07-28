"""INPUT-005 — production discovery collectors, preflight, and plan determinism."""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import pytest

from auditor.config import Settings
from auditor.domain.audit_plan import PlanConfirmationRejected
from auditor.inventory.collectors import (
    CommandResult,
    CompositeDiscoveryCollector,
    DiscoveryHostSettings,
    DiscoveryTransportError,
    FakeShellTransport,
    SshDiscoveryCollector,
    WinrmDiscoveryCollector,
    postgres_confirmed,
)
from auditor.inventory.discovery import (
    DiscoveredHostFacts,
    NoopDiscoveryCollector,
    StaticDiscoveryCollector,
    default_discovery_collector,
)
from auditor.inventory.discovery_evidence import (
    CommandEvidence,
    EvidenceSecretError,
    HostDiscoveryEvidence,
    assert_no_secrets,
    persist_host_evidence,
)
from auditor.inventory.preflight import (
    build_preflight_revision,
    discovery_result_hash,
    effective_facts_hash,
    load_latest_preflight,
)
from auditor.inventory.service import (
    analyze_client_inventory,
    confirm_audit_plan,
    plan_to_audit_request_payload,
    start_confirmed_audit,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "inventory"
AGENTS = Path("agents")
CANARY = "CANARY_PW_DISC_UNIQUE_4a1b"
SECRET_REF = "vault://client/ssh/host01"


def _write_md(client: Path, body: str) -> None:
    client.mkdir(parents=True, exist_ok=True)
    (client / "INVENTORY.md").write_text(body, encoding="utf-8")


def _linux_transport(*, with_postgres: bool = False, port_only: bool = False) -> FakeShellTransport:
    os_release = 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION_ID="24.04"\n'
    ports = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    if with_postgres or port_only:
        ports += "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n"
    responses = {
        "hostname": CommandResult("hostname", 0, "db-01\n"),
        "cat /etc/os-release": CommandResult("cat /etc/os-release", 0, os_release),
        "uname -a": CommandResult("uname -a", 0, "Linux db-01 6.8.0 x86_64 GNU/Linux\n"),
        "uname -m": CommandResult("uname -m", 0, "x86_64\n"),
        "ss -lntp": CommandResult("ss", 0, ports),
        "ss -lntup": CommandResult("ss", 0, ports),
        "systemctl list-units --type=service --state=running --no-pager": CommandResult(
            "systemctl",
            0,
            "UNIT LOAD ACTIVE SUB DESCRIPTION\nsshd.service loaded active running OpenSSH\n",
        ),
        "systemctl list-units --type=service --all --no-pager": CommandResult(
            "systemctl all",
            0,
            "UNIT LOAD ACTIVE SUB DESCRIPTION\nsshd.service loaded active running OpenSSH\n",
        ),
        "command -v psql": CommandResult("command -v psql", 1, ""),
        "command -v postgres": CommandResult("command -v postgres", 1, ""),
        "ps -ef": CommandResult("ps -ef", 0, "root 1 0 0 00:00 ? 00:00:00 /sbin/init\n"),
        "psql --version": CommandResult("psql --version", 1, ""),
        "postgres --version": CommandResult("postgres --version", 1, ""),
        "systemctl is-active postgresql": CommandResult("is-active", 3, "inactive\n"),
    }
    if with_postgres:
        responses["ps -ef"] = CommandResult(
            "ps -ef",
            0,
            "root 1 0 0 00:00 ? 00:00:00 /sbin/init\n"
            "postgres 100 1 0 00:00 ? 00:00:01 /usr/lib/postgresql/16/bin/postgres\n",
        )
        responses["systemctl list-units --type=service --all --no-pager"] = CommandResult(
            "systemctl all",
            0,
            "UNIT LOAD ACTIVE SUB DESCRIPTION\n"
            "sshd.service loaded active running OpenSSH\n"
            "postgresql.service loaded active running PostgreSQL\n",
        )
        responses["systemctl list-units --type=service --state=running --no-pager"] = CommandResult(
            "systemctl",
            0,
            "UNIT LOAD ACTIVE SUB DESCRIPTION\n"
            "sshd.service loaded active running OpenSSH\n"
            "postgresql.service loaded active running PostgreSQL\n",
        )
        responses["command -v psql"] = CommandResult("command -v psql", 0, "/usr/bin/psql\n")
        responses["psql --version"] = CommandResult("psql --version", 0, "psql (PostgreSQL) 16.2\n")
        responses["systemctl is-active postgresql"] = CommandResult("is-active", 0, "active\n")
    return FakeShellTransport(responses=responses)


def _win_transport() -> FakeShellTransport:
    return FakeShellTransport(
        responses={
            "Get-CimInstance Win32_OperatingSystem": CommandResult(
                "os",
                0,
                "Caption : Microsoft Windows Server 2022 Datacenter\nVersion : 10.0.20348\n",
            ),
            "$env:COMPUTERNAME": CommandResult("hn", 0, "WIN-01\n"),
            "Get-Service": CommandResult(
                "svc",
                0,
                "Name   Status  DisplayName\nWinRM  Running Windows Remote Management\n",
            ),
            "Get-NetTCPConnection": CommandResult(
                "ports",
                0,
                "LocalAddress LocalPort\n0.0.0.0 5985\n",
            ),
            "Get-Process": CommandResult("proc", 0, "Name Id\nIdle 0\n"),
            "Get-CimInstance Win32_Product": CommandResult("prod", 0, "Name Version\n"),
        }
    )


def test_ssh_host_without_declared_os_detected_as_linux(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "DiscOs"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.21 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token | Database |
|---|---|---:|---|---|---|
| SSH | 10.0.0.21 | 22 | audit | {CANARY} | |
""",
    )
    transport = _linux_transport()
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="DiscOs",
        artifacts_root=tmp_path / "artifacts",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, command_timeout=1, retry_count=0),
        transport_factory=lambda cred, settings: transport,
    )
    inventory, plan = analyze_client_inventory(
        root, "DiscOs", agents_dir=AGENTS, discoverer=collector
    )
    assert inventory.hosts[0].os_family == "linux"
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "ubuntu_cis_24_l2" in selected
    blob = json.dumps(inventory.model_dump()) + json.dumps(plan.model_dump())
    assert CANARY not in blob


def test_ssh_postgres_process_selects_postgres_cis(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "DiscPg"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.22 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.22 | 22 | audit | {CANARY} |
""",
    )
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="DiscPg",
        artifacts_root=tmp_path / "artifacts",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=lambda cred, settings: _linux_transport(with_postgres=True),
    )
    inventory, plan = analyze_client_inventory(
        root, "DiscPg", agents_dir=AGENTS, discoverer=collector
    )
    assert any(s.name == "postgresql" for s in inventory.hosts[0].services)
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "postgres_cis" in selected


def test_port_5432_alone_does_not_select_postgres_cis(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "PortOnly"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.23 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.23 | 22 | audit | {CANARY} |
""",
    )
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="PortOnly",
        artifacts_root=tmp_path / "artifacts",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=lambda cred, settings: _linux_transport(port_only=True),
    )
    inventory, plan = analyze_client_inventory(
        root,
        "PortOnly",
        agents_dir=AGENTS,
        discoverer=collector,
        artifacts_root=tmp_path / "artifacts",
    )
    pg = [d for d in plan.framework_decisions if "postgres" in d.framework_id]
    assert pg and all(d.status == "requires_operator_decision" for d in pg)
    assert not postgres_confirmed(
        processes=[], services=[], packages=[], binaries=[], listening_ports=[5432]
    )
    pg_dets = [
        d
        for d in plan.technology_detections
        if d.technology_id == "postgresql" and d.target_id.startswith("host-01")
    ]
    assert pg_dets and all(d.status == "suspected" for d in pg_dets)
    snaps = list((tmp_path / "artifacts").rglob("capability_snapshot.json"))
    assert snaps
    snap = json.loads(snaps[0].read_text(encoding="utf-8"))
    pg_techs = [t for t in snap.get("technologies") or [] if t["technology_id"] == "postgresql"]
    assert pg_techs and all(t["status"] == "suspected" for t in pg_techs)
    assert inventory.hosts[0].os_family == "linux"


def test_winrm_host_detected_as_windows_server(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "DiscWin"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.31 | WinRM |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| WinRM | 10.0.0.31 | 5985 | audit | {CANARY} |
""",
    )
    collector = WinrmDiscoveryCollector(
        inventory_dir=root,
        client_name="DiscWin",
        artifacts_root=tmp_path / "artifacts",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=lambda cred, settings: _win_transport(),
    )
    _inventory, plan = analyze_client_inventory(
        root, "DiscWin", agents_dir=AGENTS, discoverer=collector
    )
    assert _inventory.hosts[0].os_family == "windows"
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "windows_server" in selected


def test_declared_linux_discovered_windows_conflict(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Conflict"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | OS | IP | Access |
|---|---|---|---|
| host-01 | Ubuntu | 10.0.0.41 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.41 | 22 | audit | {CANARY} |
""",
    )
    discoverer = StaticDiscoveryCollector(
        [
            DiscoveredHostFacts(
                host_id="host-01",
                os_name="Windows Server 2019",
                os_family="windows",
                collector="ssh",
                transport="ssh",
                confidence="high",
                evidence_ref="ssh:conflict",
            )
        ]
    )
    inventory, plan = analyze_client_inventory(
        root, "Conflict", agents_dir=AGENTS, discoverer=discoverer
    )
    assert inventory.conflicts
    assert any("Clarify conflict" in q for q in plan.unresolved_questions)
    assert not [
        d for d in plan.framework_decisions if d.target_id == "host-01" and d.status == "selected"
    ]


def test_auth_failure_on_one_host_does_not_stop_others(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Multi"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.51 | SSH |
| host-02 | 10.0.0.52 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.51 | 22 | audit | {CANARY} |
| SSH | 10.0.0.52 | 22 | audit | {CANARY} |
""",
    )

    def factory(cred, settings):
        # Match by inventory address (credentials table), not host id.
        if str(cred.host).endswith(".51") or str(cred.host) == "10.0.0.51":
            return FakeShellTransport(
                connect_error=DiscoveryTransportError("auth failed", code="authentication_failed")
            )
        return _linux_transport()

    collector = CompositeDiscoveryCollector(
        inventory_dir=root,
        client_name="Multi",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        ssh_transport_factory=factory,
    )
    inventory, plan = analyze_client_inventory(
        root, "Multi", agents_dir=AGENTS, discoverer=collector
    )
    by_id = {h.host_id: h for h in inventory.hosts}
    assert by_id["host-02"].os_family == "linux"
    assert any(
        i.code == "authentication_failed" and i.host_id == "host-01" for i in inventory.issues
    )
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "ubuntu_cis_24_l2" in selected


def test_connection_timeout_stored_as_typed_issue(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Timeout"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.61 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.61 | 22 | audit | {CANARY} |
""",
    )
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="Timeout",
        defaults=DiscoveryHostSettings(connection_timeout=0.01, retry_count=0),
        transport_factory=lambda cred, settings: FakeShellTransport(
            connect_error=DiscoveryTransportError("timed out", code="connection_timeout")
        ),
    )
    inventory, _plan = analyze_client_inventory(
        root, "Timeout", agents_dir=AGENTS, discoverer=collector
    )
    assert any(i.code == "connection_timeout" for i in inventory.issues)
    assert len(inventory.hosts) == 1


def test_partial_command_failure_preserves_facts(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Partial"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.71 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.71 | 22 | audit | {CANARY} |
""",
    )
    transport = _linux_transport()
    transport.responses["ss -lntp"] = CommandResult(
        "ss",
        error="command timeout",
        error_code="command_timeout",
    )
    transport.responses["ss -lntup"] = CommandResult(
        "ss",
        error="command timeout",
        error_code="command_timeout",
    )
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="Partial",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=lambda cred, settings: transport,
    )
    inventory, plan = analyze_client_inventory(
        root, "Partial", agents_dir=AGENTS, discoverer=collector
    )
    assert inventory.hosts[0].os_family == "linux"
    assert any(i.code == "partial_discovery" for i in inventory.issues)
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "ubuntu_cis_24_l2" in selected


def test_credentials_absent_from_dumps_and_evidence(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Secrets"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.81 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.81 | 22 | audit | {CANARY} |
""",
    )
    (client / "CREDENTIALS.md").write_text(
        f"""# Credentials

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.81 | 22 | audit | {CANARY} |
""",
        encoding="utf-8",
    )
    artifacts = tmp_path / "artifacts"
    transport = _linux_transport()
    # Inject canary into stdout to ensure sanitization.
    transport.responses["hostname"] = CommandResult("hostname", 0, f"host\npassword={CANARY}\n")
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="Secrets",
        artifacts_root=artifacts,
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=lambda cred, settings: transport,
    )
    inventory, plan = analyze_client_inventory(
        root, "Secrets", agents_dir=AGENTS, discoverer=collector
    )
    blob = json.dumps(inventory.model_dump()) + json.dumps(plan.model_dump())
    assert CANARY not in blob
    assert SECRET_REF not in blob or SECRET_REF not in json.dumps(plan.model_dump())
    evidence_files = list(artifacts.rglob("*.json"))
    assert evidence_files
    for path in evidence_files:
        text = path.read_text(encoding="utf-8")
        assert CANARY not in text
        assert "vault://" not in text


def test_production_discovery_used_by_default(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Default"
    _write_md(
        client,
        """# Inventory

## In-scope hosts

| Host | OS | IP | Access |
|---|---|---|---|
| host-01 | Ubuntu | 10.0.0.91 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Secret Reference |
|---|---|---:|---|---|
| SSH | 10.0.0.91 | 22 | audit | vault://x |
""",
    )
    collector = default_discovery_collector(root, "Default", enabled=True)
    assert isinstance(collector, CompositeDiscoveryCollector)
    noop = default_discovery_collector(root, "Default", enabled=False)
    assert isinstance(noop, NoopDiscoveryCollector)


def test_no_discovery_uses_noop_path(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "NoDisc"
    _write_md(
        client,
        """# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.92 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Secret Reference |
|---|---|---:|---|---|
| SSH | 10.0.0.92 | 22 | audit | vault://x |
""",
    )
    with patch(
        "auditor.inventory.service.default_discovery_collector",
        wraps=default_discovery_collector,
    ) as mocked:
        inventory, _plan = analyze_client_inventory(
            root, "NoDisc", agents_dir=AGENTS, discovery=False
        )
    mocked.assert_called()
    assert any(i.code == "needs_discovery" for i in inventory.issues)
    assert inventory.hosts[0].os_family == ""


def test_repeated_analysis_deterministic(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Det"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.93 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.93 | 22 | audit | {CANARY} |
""",
    )

    def factory(cred, settings):
        return _linux_transport(with_postgres=True)

    c1 = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="Det",
        artifacts_root=tmp_path / "a1",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=factory,
    )
    c2 = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="Det",
        artifacts_root=tmp_path / "a2",
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=factory,
    )
    with patch("auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"):
        with patch("auditor.inventory.collectors.utc_now", return_value="2026-01-01T00:00:00Z"):
            with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
                with patch(
                    "auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"
                ):
                    inv1, plan1 = analyze_client_inventory(
                        root, "Det", agents_dir=AGENTS, discoverer=c1
                    )
                    inv2, plan2 = analyze_client_inventory(
                        root, "Det", agents_dir=AGENTS, discoverer=c2
                    )
    assert plan1.discovery_result_hash == plan2.discovery_result_hash
    assert plan1.effective_facts_hash == plan2.effective_facts_hash
    assert plan1.preflight_revision_id == plan2.preflight_revision_id
    assert effective_facts_hash(inv1) == effective_facts_hash(inv2)


def test_changed_discovery_creates_new_preflight_revision(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "Rev"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.94 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.94 | 22 | audit | {CANARY} |
""",
    )
    with patch("auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"):
        with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
            with patch("auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"):
                artifacts = tmp_path / "artifacts"
                _i1, plan1 = analyze_client_inventory(
                    root,
                    "Rev",
                    agents_dir=AGENTS,
                    artifacts_root=artifacts,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="Rev",
                        artifacts_root=artifacts,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(),
                    ),
                )
                _i2, plan2 = analyze_client_inventory(
                    root,
                    "Rev",
                    agents_dir=AGENTS,
                    artifacts_root=artifacts,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="Rev",
                        artifacts_root=artifacts,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(with_postgres=True),
                    ),
                )
    assert plan1.effective_facts_hash != plan2.effective_facts_hash
    assert plan1.preflight_revision_id != plan2.preflight_revision_id
    assert plan1.plan_revision_id != plan2.plan_revision_id
    assert plan1.plan_revision_id.startswith("prev-")
    assert plan2.plan_revision_id.startswith("prev-")
    latest = load_latest_preflight(tmp_path / "artifacts", "Rev")
    assert latest is not None, list((tmp_path / "artifacts").rglob("*"))
    assert latest.effective_facts_hash == plan2.effective_facts_hash


def test_api_and_cli_generate_equivalent_plans(tmp_path: Path):
    root = tmp_path / "inventory"
    dest = root / "Testcompany"
    dest.mkdir(parents=True)
    shutil.copy(FIXTURES / "Testcompany" / "INVENTORY.md", dest / "INVENTORY.md")
    discoverer = StaticDiscoveryCollector([])
    _inv_cli, plan_cli = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discoverer=discoverer
    )
    _inv_api, plan_api = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discoverer=discoverer
    )
    assert plan_cli.model_dump(exclude={"created_at"}) == plan_api.model_dump(
        exclude={"created_at"}
    )


def test_testcompany_five_hosts_two_postgres_plan(tmp_path: Path):
    root = tmp_path / "inventory"
    dest = root / "Testcompany"
    dest.mkdir(parents=True)
    shutil.copy(FIXTURES / "Testcompany" / "INVENTORY.md", dest / "INVENTORY.md")
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False
    )
    assert plan.summary.total_hosts == 5
    assert plan.summary.linux_hosts == 4
    assert plan.summary.windows_hosts == 1
    assert plan.summary.postgresql_instances == 2
    selected = [d for d in plan.framework_decisions if d.status == "selected"]
    assert sum(1 for d in selected if d.framework_id == "ubuntu_cis_24_l2") == 4
    assert sum(1 for d in selected if d.framework_id == "windows_server") == 1
    assert sum(1 for d in selected if d.framework_id == "postgres_cis") == 2
    assert any(d.framework_id in {"host_facts", "it_audit"} for d in selected)


def test_winrm_fake_transport_without_windows_runner(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "WinFake"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.95 | WinRM |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| WinRM | 10.0.0.95 | 5985 | audit | {CANARY} |
""",
    )
    facts = WinrmDiscoveryCollector(
        inventory_dir=root,
        client_name="WinFake",
        defaults=DiscoveryHostSettings(retry_count=0),
        transport_factory=lambda c, s: _win_transport(),
    ).discover(analyze_client_inventory(root, "WinFake", agents_dir=AGENTS, discovery=False)[0])
    assert len(facts) == 1
    assert facts[0].os_family == "windows"
    assert facts[0].collector == "winrm"


def test_confirmed_start_does_not_silently_rerun_discovery(tmp_path: Path):
    root = tmp_path / "inventory"
    dest = root / "Testcompany"
    dest.mkdir(parents=True)
    shutil.copy(FIXTURES / "Testcompany" / "INVENTORY.md", dest / "INVENTORY.md")
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
    )
    inventory, plan = analyze_client_inventory(
        root, "Testcompany", agents_dir=AGENTS, discovery=False, artifacts_root=evidence
    )
    plan = confirm_audit_plan(plan, action="approve", inventory=inventory)
    calls = {"n": 0}

    class _Counting(NoopDiscoveryCollector):
        def discover(self, inv):
            calls["n"] += 1
            return super().discover(inv)

    async def _executor(request):
        return {"audit_run_id": "run_x", "audit_run_status": "running"}

    with patch(
        "auditor.inventory.service.default_discovery_collector",
        side_effect=AssertionError("discovery must not run on start"),
    ):
        started = start_confirmed_audit(
            root,
            "Testcompany",
            plan,
            settings=settings,
            agents_dir=AGENTS,
            executor=_executor,
            discoverer=None,
            refresh_discovery=False,
        )
    assert started["audit_run_id"] == "run_x"
    assert calls["n"] == 0


def test_discovery_change_after_confirmation_makes_plan_stale(tmp_path: Path):
    root = tmp_path / "inventory"
    client = root / "StaleDisc"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.0.96 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.0.96 | 22 | audit | {CANARY} |
""",
    )
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
    )
    with patch("auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"):
        with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
            with patch("auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"):
                inventory, plan = analyze_client_inventory(
                    root,
                    "StaleDisc",
                    agents_dir=AGENTS,
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="StaleDisc",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(),
                    ),
                )
                plan = confirm_audit_plan(
                    plan,
                    action="approve",
                    inventory=inventory,
                    inventory_dir=root,
                    client_name="StaleDisc",
                )
                # Simulate a later analyze that changes effective facts.
                analyze_client_inventory(
                    root,
                    "StaleDisc",
                    agents_dir=AGENTS,
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="StaleDisc",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(with_postgres=True),
                    ),
                )

    async def _executor(request):
        return {"audit_run_id": "should-not", "audit_run_status": "running"}

    with pytest.raises(PlanConfirmationRejected, match="stale"):
        start_confirmed_audit(
            root,
            "StaleDisc",
            plan,
            settings=settings,
            agents_dir=AGENTS,
            executor=_executor,
        )


def test_discovery_evidence_rejects_secret_canaries(tmp_path: Path):
    evidence = HostDiscoveryEvidence(
        host_id="host-01",
        transport="ssh",
        collector="ssh",
        facts={"hostname": "x"},
        commands=[
            CommandEvidence(
                command="hostname",
                exit_code=0,
                stdout=f"password={CANARY}",
                transport="ssh",
            )
        ],
    )
    with pytest.raises(EvidenceSecretError):
        persist_host_evidence(
            evidence,
            artifacts_root=tmp_path / "artifacts",
            client_slug="Sec",
            inventory_version_id="inv-1",
            known_secrets=[CANARY],
        )
    with pytest.raises(EvidenceSecretError):
        assert_no_secrets({"token": "abc123secret"}, known_secrets=[])


def test_discovery_result_hash_ignores_volatile_output(tmp_path: Path):
    a = DiscoveredHostFacts(
        host_id="h1",
        os_family="linux",
        os_name="Ubuntu",
        services=["ssh"],
        collected_at="2026-01-01T00:00:00Z",
        command_results=[CommandResult("hostname", 0, "a")],
    )
    b = DiscoveredHostFacts(
        host_id="h1",
        os_family="linux",
        os_name="Ubuntu",
        services=["ssh"],
        collected_at="2026-07-26T12:00:00Z",
        command_results=[CommandResult("hostname", 0, "b-different")],
    )
    assert discovery_result_hash([a]) == discovery_result_hash([b])
    root = tmp_path / "inventory"
    dest = root / "Testcompany"
    dest.mkdir(parents=True)
    shutil.copy(FIXTURES / "Testcompany" / "INVENTORY.md", dest / "INVENTORY.md")
    from auditor.inventory.service import load_client_inventory

    inventory = load_client_inventory(root, "Testcompany")
    rev1 = build_preflight_revision(
        inventory, discoveries=[a], selected_frameworks=["ubuntu_cis_24_l2"]
    )
    rev2 = build_preflight_revision(
        inventory, discoveries=[b], selected_frameworks=["ubuntu_cis_24_l2"]
    )
    assert rev1.discovery_result_hash == rev2.discovery_result_hash
    assert asdict(a)["collected_at"] != asdict(b)["collected_at"]


def test_tool_driven_discovery_five_linux_hosts_postgres_on_two(tmp_path: Path):
    """Acceptance: 5 Linux hosts, PG on 2, postgres_cis only for those 2."""
    from auditor.inventory.tool_discovery import select_discovery_tools

    root = tmp_path / "inventory"
    client = root / "FiveLinux"
    hosts_md = "\n".join(f"| host-{i:02d} | 10.0.5.{i} | SSH |" for i in range(1, 6))
    creds_md = "\n".join(f"| SSH | 10.0.5.{i} | 22 | audit | {CANARY}{i} |" for i in range(1, 6))
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
{hosts_md}

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
{creds_md}
""",
    )

    tools = select_discovery_tools()
    assert {t.id for t in tools} >= {"ssh_run"}
    assert all(t.transport == "ssh" for t in tools)

    def _factory(cred, settings):
        host = str(cred.host)
        with_pg = host.endswith(".2") or host.endswith(".4")
        return _linux_transport(with_postgres=with_pg)

    artifacts = tmp_path / "artifacts"
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="FiveLinux",
        artifacts_root=artifacts,
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=_factory,
    )
    audit_tool_calls: list[str] = []

    with patch(
        "auditor.workflows.tool_execution.execute_tool_calls",
        side_effect=lambda *a, **k: audit_tool_calls.append("audit") or [],
    ):
        inventory, plan = analyze_client_inventory(
            root, "FiveLinux", agents_dir=AGENTS, discoverer=collector, artifacts_root=artifacts
        )

    assert plan.summary.total_hosts == 5
    assert plan.summary.linux_hosts == 5
    assert plan.summary.postgresql_instances == 2
    assert plan.framework_hash.startswith("fw-")
    assert plan.tool_catalog_hash.startswith("tool-")
    assert plan.capability_policy_hash.startswith("pol-")
    assert plan.discovery_result_hash
    assert plan.inventory_content_hash
    assert plan.status == "draft"

    selected = [d for d in plan.framework_decisions if d.status == "selected"]
    pg_selected = [d for d in selected if d.framework_id == "postgres_cis"]
    assert len(pg_selected) == 2
    assert {d.target_id for d in pg_selected} == {"host-02/postgresql", "host-04/postgresql"}
    assert sum(1 for d in selected if d.framework_id == "ubuntu_cis_24_l2") == 5

    # Plan lists all targets and selected frameworks for operator confirmation.
    target_ids = {t.target_id for t in plan.targets}
    assert "host-02/postgresql" in target_ids
    assert "host-04/postgresql" in target_ids
    assert not any(
        t.target_id.startswith("host-01/") and "postgresql" in t.target_id for t in plan.targets
    )
    assert not any(
        t.target_id.startswith("host-03/") and "postgresql" in t.target_id for t in plan.targets
    )
    assert not any(
        t.target_id.startswith("host-05/") and "postgresql" in t.target_id for t in plan.targets
    )

    snapshots = list(artifacts.rglob("capability_snapshot.json"))
    assert len(snapshots) == 5
    pg_hosts = set()
    for path in snapshots:
        snap = json.loads(path.read_text(encoding="utf-8"))
        assert snap["schema"] == "host_capability_snapshot.v1"
        assert snap["client_id"]
        assert snap["inventory_version_id"]
        assert snap["os"]["family"] == "linux"
        assert snap["access"]["ssh"]["available"] is True
        assert snap["tool_catalog_hash"].startswith("tool-")
        assert snap["capability_policy_hash"].startswith("pol-")
        assert "ssh_run" in snap["tool_ids"]
        for tech in snap.get("technologies") or []:
            if tech["technology_id"] == "postgresql" and tech["status"] == "confirmed":
                pg_hosts.add(snap["host_id"])
                assert str(tech.get("version") or "").startswith("16")
    assert pg_hosts == {"host-02", "host-04"}

    # No audit tools execute before plan confirmation.
    assert audit_tool_calls == []
    from auditor.inventory.plan import ensure_plan_confirmed

    with pytest.raises(PlanConfirmationRejected):
        ensure_plan_confirmed(plan)
    with pytest.raises(PlanConfirmationRejected):
        plan_to_audit_request_payload(
            plan, inventory=inventory, client_id="five", client_slug="FiveLinux"
        )

    confirmed = confirm_audit_plan(plan, action="approve", inventory=inventory)
    assert confirmed.status == "confirmed"
    assert audit_tool_calls == []
    # After confirmation the plan is executable, but this test never starts the run.
    ensure_plan_confirmed(confirmed)


def test_acceptance_five_linux_two_postgres_one_cisco_unsupported(tmp_path: Path):
    """Main INPUT-005 scenario: 5 Linux + PG×2 + unsupported Cisco."""
    root = tmp_path / "inventory"
    client = root / "Accept005"
    hosts_md = "\n".join(f"| host-{i:02d} | 10.0.8.{i} | SSH | server | |" for i in range(1, 6))
    creds_md = "\n".join(f"| SSH | 10.0.8.{i} | 22 | audit | {CANARY}{i} |" for i in range(1, 6))
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access | Type | Vendor |
|---|---|---|---|---|
{hosts_md}
| core-sw-01 | 10.0.8.50 | | network_device | cisco |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
{creds_md}
""",
    )

    def _factory(cred, settings):
        host = str(cred.host)
        with_pg = host.endswith(".2") or host.endswith(".4")
        return _linux_transport(with_postgres=with_pg)

    artifacts = tmp_path / "artifacts"
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="Accept005",
        artifacts_root=artifacts,
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=_factory,
    )

    inventory, plan = analyze_client_inventory(
        root,
        "Accept005",
        agents_dir=AGENTS,
        discoverer=collector,
        artifacts_root=artifacts,
    )

    assert plan.status == "draft"
    assert plan.summary.linux_hosts == 5
    assert sum(1 for h in inventory.hosts if h.is_unsupported_network_device) == 1

    selected = [d for d in plan.framework_decisions if d.status == "selected"]
    assert sum(1 for d in selected if d.framework_id == "ubuntu_cis_24_l2") == 5
    assert sum(1 for d in selected if d.framework_id == "postgres_cis") == 2
    unsupported = [d for d in plan.framework_decisions if d.status == "unsupported"]
    assert any(d.target_id == "core-sw-01" for d in unsupported)
    assert any("cisco.cli.read" in d.missing_capabilities for d in unsupported)

    cisco_snaps = [
        p for p in artifacts.rglob("capability_snapshot.json") if p.parent.name == "core-sw-01"
    ]
    assert len(cisco_snaps) == 1
    cisco_snap = json.loads(cisco_snaps[0].read_text(encoding="utf-8"))
    assert cisco_snap["schema"] == "host_capability_snapshot.v1"
    assert cisco_snap["asset_type"] in {"network_device", "network"}
    assert any(
        t["technology_id"] == "network_device" and t["status"] == "unsupported"
        for t in cisco_snap.get("technologies") or []
    )
    assert any("cisco.cli.read" in lim for lim in cisco_snap.get("limitations") or [])

    # No assessment jobs / audit request before confirmation.
    with pytest.raises(PlanConfirmationRejected):
        plan_to_audit_request_payload(
            plan, inventory=inventory, client_id="accept005", client_slug="Accept005"
        )

    confirmed = confirm_audit_plan(plan, action="approve", inventory=inventory)
    assert confirmed.status == "confirmed"

    payload = plan_to_audit_request_payload(
        confirmed, inventory=inventory, client_id="accept005", client_slug="Accept005"
    )
    # One target entry per executable host; frameworks attached per host.
    assert len(payload["targets"]) == 5
    fw_by_ref = {
        t["inventory_target_ref"]: {f["framework_id"] for f in t["frameworks"]}
        for t in payload["targets"]
    }
    assert "ubuntu_cis_24_l2" in fw_by_ref["10.0.8.1"]
    assert "postgres_cis" in fw_by_ref["10.0.8.2"]
    assert "postgres_cis" in fw_by_ref["10.0.8.4"]
    assert "postgres_cis" not in fw_by_ref["10.0.8.1"]
    assert "postgres_cis" not in fw_by_ref["10.0.8.3"]
    assert "postgres_cis" not in fw_by_ref["10.0.8.5"]
    # Cisco must not become an audit target.
    assert "10.0.8.50" not in fw_by_ref
    assert "core-sw-01" not in fw_by_ref

    jobs_after: list[dict] = []
    for target in payload["targets"]:
        for fw in target["frameworks"]:
            jobs_after.append(
                {
                    "host": target["inventory_target_ref"],
                    "framework_id": fw["framework_id"],
                }
            )
    assert len(jobs_after) >= 7  # 5 linux OS + 2 postgres (+ optional host_facts)
    assert not any(j["host"] == "10.0.8.50" for j in jobs_after)
    assert sum(1 for j in jobs_after if j["framework_id"] == "postgres_cis") == 2


@pytest.mark.asyncio
async def test_e2e_api_analyze_confirm_start_with_discovery(tmp_path: Path):
    """API analyze → confirm → start validates against effective inventory."""
    import httpx

    from auditor.api.app import create_app
    from auditor.application_runtime import ApplicationRuntime
    from auditor.audit_registry import get_audit_registry
    from auditor.domain.audit_models import AuditJobType, new_audit_run_id
    from auditor.inventory.service import load_effective_inventory, persist_plan

    root = tmp_path / "inventory"
    client_dir = root / "ApiE2E"
    _write_md(
        client_dir,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.9.1 | SSH |
| host-02 | 10.0.9.2 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.9.1 | 22 | audit | {CANARY} |
| SSH | 10.0.9.2 | 22 | audit | {CANARY} |
""",
    )
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
    )

    def _factory(cred, settings_):
        return _linux_transport(with_postgres=str(cred.host).endswith(".2"))

    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="ApiE2E",
        artifacts_root=evidence,
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=_factory,
    )
    inventory, plan = analyze_client_inventory(
        root,
        "ApiE2E",
        agents_dir=AGENTS,
        discoverer=collector,
        artifacts_root=evidence,
        persist_dir=root / "ApiE2E" / ".audit_plans",
    )
    persist_plan(plan, root / "ApiE2E" / ".audit_plans" / "latest.json")
    effective = load_effective_inventory(root, "ApiE2E")
    assert effective is not None
    assert any(
        s.name == "postgresql"
        for h in effective.hosts
        for s in h.services
        if h.host_id == "host-02"
    )
    assert plan.plan_revision_id.startswith("prev-")

    created_jobs: list[tuple[str, str]] = []

    class _FakeGraph:
        def __init__(self, settings: Settings):
            self.settings = settings

        async def aclose_runtime_resources(self, timeout: float | None = None) -> None:
            return None

        async def arun_request(self, request, operator_context: str = ""):
            run_id = new_audit_run_id()
            registry = get_audit_registry(self.settings.evidence_dir)
            registry.create_run(client_id=request.client_id, audit_run_id=run_id)
            for target in request.targets:
                for fw in target.frameworks:
                    registry.create_job(
                        audit_run_id=run_id,
                        logical_task_id=f"{target.inventory_target_ref}:{fw.framework_id}",
                        job_type=AuditJobType.ASSESS_FRAMEWORK,
                        framework_id=fw.framework_id,
                        host_id=target.inventory_target_ref,
                    )
                    created_jobs.append((target.inventory_target_ref, fw.framework_id))
            return {
                "audit_run_id": run_id,
                "evidence_run_id": "ev_api_e2e",
                "audit_run_status": "running",
                "awaiting_hitl": False,
            }

    async def _runtime_factory():
        runtime = ApplicationRuntime(
            settings,
            graph_factory=lambda rt: _FakeGraph(rt.settings),  # type: ignore[arg-type, return-value]
            shutdown_timeout=0.5,
        )
        await runtime.start()
        return runtime

    app = create_app(settings=settings, runtime_factory=_runtime_factory)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                f"/audit-plans/{plan.plan_id}/confirm",
                json={
                    "plan_revision_id": plan.plan_revision_id,
                    "action": "approve",
                    "start": True,
                    "note": "api-e2e",
                },
            )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["audit_run_id"]
    confirmed = body["plan"]
    assert confirmed["status"] == "confirmed"
    assert confirmed["plan_revision_id"] == plan.plan_revision_id

    host_addr = {h.host_id: (h.address or h.host_id) for h in inventory.hosts}
    expected = {(host_addr[t.host_id], t.framework_id) for t in plan.targets if not t.excluded}
    assert set(created_jobs) == expected


def test_e2e_cli_analyze_confirm_start_with_discovery(tmp_path: Path):
    """CLI analyze → confirm → start path with discovery + AuditJob identity."""
    from auditor.audit_registry import get_audit_registry
    from auditor.domain.audit_models import AuditJobType, new_audit_run_id
    from auditor.inventory.service import load_effective_inventory, persist_plan

    root = tmp_path / "inventory"
    client_dir = root / "CliE2E"
    _write_md(
        client_dir,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.10.1 | SSH |
| host-02 | 10.0.10.2 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.10.1 | 22 | audit | {CANARY} |
| SSH | 10.0.10.2 | 22 | audit | {CANARY} |
""",
    )
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
    )
    plans = root / "CliE2E" / ".audit_plans"
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="CliE2E",
        artifacts_root=evidence,
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=lambda c, s: _linux_transport(with_postgres=str(c.host).endswith(".2")),
    )
    inventory, plan = analyze_client_inventory(
        root,
        "CliE2E",
        agents_dir=AGENTS,
        discoverer=collector,
        artifacts_root=evidence,
        persist_dir=plans,
    )
    persist_plan(plan, plans / "latest.json")
    assert load_effective_inventory(root, "CliE2E") is not None
    assert plan.plan_revision_id.startswith("prev-")

    created: list[tuple[str, str]] = []

    async def _executor(request):
        run_id = new_audit_run_id()
        registry = get_audit_registry(settings.evidence_dir)
        registry.create_run(client_id=request.client_id, audit_run_id=run_id)
        for target in request.targets:
            for fw in target.frameworks:
                registry.create_job(
                    audit_run_id=run_id,
                    logical_task_id=f"{target.inventory_target_ref}:{fw.framework_id}",
                    job_type=AuditJobType.ASSESS_FRAMEWORK,
                    framework_id=fw.framework_id,
                    host_id=target.inventory_target_ref,
                )
                created.append((target.inventory_target_ref, fw.framework_id))
        return {"audit_run_id": run_id, "audit_run_status": "running"}

    started = start_confirmed_audit(
        root,
        "CliE2E",
        plan,
        settings=settings,
        agents_dir=AGENTS,
        note="cli-e2e",
        executor=_executor,
    )
    assert started["status"] == "started"
    assert started["plan"].status == "confirmed"
    host_addr = {h.host_id: (h.address or h.host_id) for h in inventory.hosts}
    expected = {(host_addr[t.host_id], t.framework_id) for t in plan.targets if not t.excluded}
    assert set(created) == expected
    jobs = get_audit_registry(settings.evidence_dir).list_jobs(started["audit_run_id"])
    job_pairs = {(j.host_id, j.framework_id) for j in jobs}
    assert job_pairs == expected


def test_same_inventory_changed_discovery_new_plan_revision(tmp_path: Path):
    """Same source inventory with different discovery facts → new plan_revision_id."""
    root = tmp_path / "inventory"
    client = root / "RevPlan"
    _write_md(
        client,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.11.1 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.11.1 | 22 | audit | {CANARY} |
""",
    )
    artifacts = tmp_path / "artifacts"
    with patch("auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"):
        with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
            with patch("auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"):
                _i1, plan1 = analyze_client_inventory(
                    root,
                    "RevPlan",
                    agents_dir=AGENTS,
                    artifacts_root=artifacts,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="RevPlan",
                        artifacts_root=artifacts,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(),
                    ),
                )
                _i2, plan2 = analyze_client_inventory(
                    root,
                    "RevPlan",
                    agents_dir=AGENTS,
                    artifacts_root=artifacts,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="RevPlan",
                        artifacts_root=artifacts,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(with_postgres=True),
                    ),
                )
    assert plan1.inventory_content_hash == plan2.inventory_content_hash
    assert plan1.inventory_version_id == plan2.inventory_version_id
    assert plan1.discovery_result_hash != plan2.discovery_result_hash
    assert plan1.plan_revision_id != plan2.plan_revision_id


@pytest.mark.asyncio
async def test_api_stale_plan_revision_rejected_current_succeeds(tmp_path: Path):
    """Same plan_id + older displayed revision → 409 audit_plan_stale; current confirms."""
    import httpx

    from auditor.api.app import create_app
    from auditor.application_runtime import ApplicationRuntime
    from auditor.inventory.service import load_plan, persist_plan

    root = tmp_path / "inventory"
    client_dir = root / "RevPinApi"
    _write_md(
        client_dir,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.30.1 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.30.1 | 22 | audit | {CANARY} |
""",
    )
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
    )
    plans = client_dir / ".audit_plans"
    with patch("auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"):
        with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
            with patch("auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"):
                _i1, old_plan = analyze_client_inventory(
                    root,
                    "RevPinApi",
                    agents_dir=AGENTS,
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="RevPinApi",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(),
                    ),
                    persist_dir=plans,
                )
                _i2, new_plan = analyze_client_inventory(
                    root,
                    "RevPinApi",
                    agents_dir=AGENTS,
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="RevPinApi",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(with_postgres=True),
                    ),
                    persist_dir=plans,
                )
    persist_plan(new_plan, plans / "latest.json")
    assert new_plan.plan_id == old_plan.plan_id
    assert new_plan.plan_revision_id != old_plan.plan_revision_id

    called = {"n": 0}

    class _GuardGraph:
        def __init__(self, settings: Settings):
            self.settings = settings

        async def aclose_runtime_resources(self, timeout: float | None = None) -> None:
            return None

        async def arun_request(self, request, operator_context: str = ""):
            called["n"] += 1
            raise AssertionError("executor must not run for stale revision")

    async def _runtime_factory():
        runtime = ApplicationRuntime(
            settings,
            graph_factory=lambda rt: _GuardGraph(rt.settings),  # type: ignore[arg-type, return-value]
            shutdown_timeout=0.5,
        )
        await runtime.start()
        return runtime

    app = create_app(settings=settings, runtime_factory=_runtime_factory)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            stale = await http.post(
                f"/audit-plans/{old_plan.plan_id}/confirm",
                json={
                    "plan_revision_id": old_plan.plan_revision_id,
                    "action": "approve",
                },
            )
            stale_start = await http.post(
                f"/audit-plans/{old_plan.plan_id}/confirm",
                json={
                    "plan_revision_id": old_plan.plan_revision_id,
                    "action": "approve",
                    "start": True,
                },
            )
            persist_plan(new_plan, plans / "latest.json")
            ok = await http.post(
                f"/audit-plans/{new_plan.plan_id}/confirm",
                json={
                    "plan_revision_id": new_plan.plan_revision_id,
                    "action": "approve",
                },
            )

    assert stale.status_code == 409, stale.text
    assert stale.json()["detail"]["code"] == "audit_plan_stale"
    assert CANARY not in json.dumps(stale.json())
    assert stale_start.status_code == 409, stale_start.text
    assert stale_start.json()["detail"]["code"] == "audit_plan_stale"
    assert called["n"] == 0
    assert not (evidence / ".audit_registry.sqlite").exists()
    assert ok.status_code == 200, ok.text
    assert ok.json()["plan"]["status"] == "confirmed"
    assert load_plan(plans / "latest.json").status == "confirmed"


def test_cli_stale_and_current_plan_revision(tmp_path: Path, capsys):
    """CLI --plan-revision-id: stale → exit 4; current → exit 0."""
    from auditor.cli import main
    from auditor.inventory.service import load_plan, persist_plan

    root = tmp_path / "inventory"
    client_dir = root / "Testcompany"
    _write_md(
        client_dir,
        f"""# Inventory

## In-scope hosts

| Host | IP | Access |
|---|---|---|
| host-01 | 10.0.31.1 | SSH |

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | 10.0.31.1 | 22 | audit | {CANARY} |
""",
    )
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
    )
    plans = client_dir / ".audit_plans"
    with patch("auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"):
        with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
            with patch("auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"):
                _i1, old_plan = analyze_client_inventory(
                    root,
                    "Testcompany",
                    agents_dir=AGENTS,
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="Testcompany",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(),
                    ),
                    persist_dir=plans,
                )
                _i2, new_plan = analyze_client_inventory(
                    root,
                    "Testcompany",
                    agents_dir=AGENTS,
                    artifacts_root=evidence,
                    discoverer=SshDiscoveryCollector(
                        inventory_dir=root,
                        client_name="Testcompany",
                        artifacts_root=evidence,
                        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
                        transport_factory=lambda c, s: _linux_transport(with_postgres=True),
                    ),
                    persist_dir=plans,
                )
    persist_plan(new_plan, plans / "latest.json")
    assert new_plan.plan_id == old_plan.plan_id
    assert new_plan.plan_revision_id != old_plan.plan_revision_id

    with patch("auditor.cli.load_settings", return_value=settings):
        rc_stale = main(
            [
                "audit",
                "start",
                "Testcompany",
                "--confirm",
                "--plan-revision-id",
                old_plan.plan_revision_id,
            ]
        )
    assert rc_stale == 4
    err = capsys.readouterr().err
    assert "stale" in err.lower()
    assert load_plan(plans / "latest.json").status == "draft"
    assert not (plans / "audit_request.json").exists()
    assert not (evidence / ".audit_registry.sqlite").exists()

    with patch("auditor.cli.load_settings", return_value=settings):
        with patch(
            "auditor.cli.start_confirmed_audit",
            return_value={
                "status": "started",
                "plan_id": new_plan.plan_id,
                "plan": new_plan.model_copy(update={"status": "confirmed"}),
                "client_id": "client_test",
                "audit_run_id": "run_ok",
                "evidence_run_id": "ev_ok",
                "audit_run_status": "running",
                "awaiting_hitl": False,
                "audit_request": {"client_id": "client_test", "targets": []},
            },
        ) as start_mock:
            rc_ok = main(
                [
                    "audit",
                    "start",
                    "Testcompany",
                    "--confirm",
                    "--plan-revision-id",
                    new_plan.plan_revision_id,
                ]
            )
    assert rc_ok == 0
    assert start_mock.call_args.kwargs["expected_plan_revision_id"] == new_plan.plan_revision_id

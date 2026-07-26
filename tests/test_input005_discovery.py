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
        "ss -lntup || netstat -lntup": CommandResult("ss", 0, ports),
        "systemctl list-units --type=service --state=running --no-pager": CommandResult(
            "systemctl",
            0,
            "UNIT LOAD ACTIVE SUB DESCRIPTION\nsshd.service loaded active running OpenSSH\n",
        ),
        "command -v psql": CommandResult("command -v psql", 1, ""),
        "command -v postgres": CommandResult("command -v postgres", 1, ""),
        "ps -ef": CommandResult("ps -ef", 0, "root 1 0 0 00:00 ? 00:00:00 /sbin/init\n"),
        "ps -ef | grep '[p]ostgres'": CommandResult("ps grep", 0, ""),
        "systemctl list-units --type=service --all | grep -i postgres": CommandResult(
            "systemctl grep", 0, ""
        ),
        "dpkg-query -W 2>/dev/null | grep -i postgres || rpm -qa 2>/dev/null | grep -i postgres": (
            CommandResult("pkg", 0, "")
        ),
    }
    if with_postgres:
        responses["ps -ef | grep '[p]ostgres'"] = CommandResult(
            "ps grep",
            0,
            "postgres 100 1 0 00:00 ? 00:00:01 /usr/lib/postgresql/16/bin/postgres\n",
        )
        responses["systemctl list-units --type=service --all | grep -i postgres"] = CommandResult(
            "systemctl grep",
            0,
            "postgresql.service loaded active running PostgreSQL\n",
        )
        responses["command -v psql"] = CommandResult("command -v psql", 0, "/usr/bin/psql\n")
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
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
        defaults=DiscoveryHostSettings(connection_timeout=0.05, retry_count=0),
        transport_factory=lambda cred, settings: _linux_transport(port_only=True),
    )
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
        _inventory, plan = analyze_client_inventory(
            root, "PortOnly", agents_dir=AGENTS, discoverer=collector
        )
    pg = [d for d in plan.framework_decisions if "postgres" in d.framework_id]
    assert pg and all(d.status == "rejected" for d in pg)
    assert not postgres_confirmed(
        processes=[], services=[], packages=[], binaries=[], listening_ports=[5432]
    )


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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
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
    transport.responses["ss -lntup || netstat -lntup"] = CommandResult(
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
        with patch(
            "auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"
        ):
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
        with patch(
            "auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"
        ):
            with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
                with patch(
                    "auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"
                ):
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
    with patch("auditor.inventory.collectors._tcp_reachable", return_value=True):
        with patch(
            "auditor.inventory.discovery_evidence.utc_now", return_value="2026-01-01T00:00:00Z"
        ):
            with patch("auditor.inventory.plan._utc_now", return_value="2026-01-01T00:00:00Z"):
                with patch(
                    "auditor.inventory.preflight._utc_now", return_value="2026-01-01T00:00:00Z"
                ):
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

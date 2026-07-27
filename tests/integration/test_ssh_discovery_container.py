"""Integration: real SSH discovery against an in-process asyncssh server.

Uses a temporary asyncssh listener (real SSH protocol) rather than external
infrastructure. Marked ``integration`` so unit runs never open sockets.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import asyncssh
import pytest

from auditor.inventory.collectors import (
    DiscoveryHostSettings,
    SshDiscoveryCollector,
)
from auditor.inventory.service import analyze_client_inventory

AGENTS = Path("agents")
PASSWORD = "test-ssh-pass-input005"


class _DiscoverySSHServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == "audit" and password == PASSWORD


def _command_output(command: str) -> str:
    if command == "hostname":
        return "ssh-integ-01\n"
    if command == "cat /etc/os-release":
        return 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION_ID="24.04"\n'
    if command == "uname -m":
        return "x86_64\n"
    if command.startswith("uname"):
        return "Linux ssh-integ-01 6.8.0 x86_64 GNU/Linux\n"
    if command in {"ss -lntp", "ss -lntup", "netstat -lntup"}:
        return "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n"
    if command == "systemctl is-active postgresql":
        return "active\n"
    if "systemctl list-units --type=service --state=running" in command:
        return (
            "sshd.service loaded active running OpenSSH server\n"
            "postgresql.service loaded active running PostgreSQL Cluster\n"
        )
    if "systemctl list-units --type=service --all" in command:
        return (
            "sshd.service loaded active running OpenSSH server\n"
            "postgresql.service loaded active running PostgreSQL Cluster\n"
        )
    if command == "command -v psql":
        return "/usr/bin/psql\n"
    if command == "command -v postgres":
        return "/usr/lib/postgresql/16/bin/postgres\n"
    if command == "psql --version":
        return "psql (PostgreSQL) 16.2\n"
    if command == "postgres --version":
        return "postgres (PostgreSQL) 16.2\n"
    if command == "ps -ef":
        return (
            "root 1 0 0 00:00 ? 00:00:00 /sbin/init\npostgres 100 1 0 00:00 ? 00:00:01 postgres\n"
        )
    return ""


async def _handle_client(process: asyncssh.SSHServerProcess) -> None:
    command = process.command or ""
    process.stdout.write(_command_output(command))
    process.stdout.write_eof()
    process.exit(0)


@pytest.fixture(scope="module")
def ssh_test_server():
    """Start a real asyncssh server on an ephemeral port in a background loop."""
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    state: dict[str, object] = {}

    async def _start_and_bind() -> None:
        server = await asyncssh.create_server(
            _DiscoverySSHServer,
            "127.0.0.1",
            0,
            server_host_keys=[asyncssh.generate_private_key("ssh-rsa")],
            process_factory=_handle_client,
        )
        state["port"] = int(server.get_port())
        state["server"] = server
        ready.set()

    def _run() -> None:
        asyncio.set_event_loop(loop)
        loop.create_task(_start_and_bind())
        loop.run_forever()

    thread = threading.Thread(target=_run, name="ssh-discovery-integ", daemon=True)
    thread.start()
    assert ready.wait(timeout=10), "SSH test server failed to start"
    port = int(state["port"])  # type: ignore[arg-type]
    yield {"host": "127.0.0.1", "port": port, "user": "audit", "password": PASSWORD}

    server = state.get("server")
    if server is not None:
        loop.call_soon_threadsafe(server.close)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5)


@pytest.mark.integration
def test_real_ssh_discovery_selects_linux_and_postgres(tmp_path: Path, ssh_test_server):
    host = ssh_test_server["host"]
    port = ssh_test_server["port"]
    root = tmp_path / "inventory"
    client = root / "SshInteg"
    client.mkdir(parents=True)
    (client / "INVENTORY.md").write_text(
        f"""# Inventory

## Credentials & Access

| Access | Host / URL | Port | Username | Password / Token |
|---|---|---:|---|---|
| SSH | {host} | {port} | audit | {PASSWORD} |

## In-scope hosts

| Host | IP | Access | Port |
|---|---|---|---:|
| host-01 | {host} | SSH | {port} |
""",
        encoding="utf-8",
    )
    artifacts = tmp_path / "artifacts"
    collector = SshDiscoveryCollector(
        inventory_dir=root,
        client_name="SshInteg",
        artifacts_root=artifacts,
        defaults=DiscoveryHostSettings(
            connection_timeout=5,
            command_timeout=10,
            retry_count=1,
        ),
    )
    inventory, plan = analyze_client_inventory(
        root,
        "SshInteg",
        agents_dir=AGENTS,
        discoverer=collector,
        artifacts_root=artifacts,
    )
    assert inventory.hosts[0].os_family == "linux"
    assert any(
        s.name == "postgresql" and s.source == "discovered" for s in inventory.hosts[0].services
    )
    selected = {d.framework_id for d in plan.framework_decisions if d.status == "selected"}
    assert "ubuntu_cis_24_l2" in selected
    assert "postgres_cis" in selected
    assert list(artifacts.rglob("discovery.json"))
    for path in artifacts.rglob("*.json"):
        assert PASSWORD not in path.read_text(encoding="utf-8")

"""Host facts parsing, drift compare, INVENTORY.md upsert."""

from pathlib import Path

from auditor.host_facts import (
    HostFacts,
    parse_binaries_present,
    parse_listening_ports,
    parse_os_release,
    upsert_inventory_md,
)


def test_parse_host_facts_json_and_merge():
    from auditor.host_facts import merge_facts_from_raw, parse_host_facts_json

    facts = parse_host_facts_json(
        {
            "hostname": "db-01",
            "ips": ["10.0.0.5", "bad"],
            "os_id": "Ubuntu",
            "os_version_id": "24.04",
            "os_pretty_name": "Ubuntu 24.04 LTS",
            "binaries": ["psql", "postgres"],
            "listening_ports": [5432, "22", "nope"],
            "cpu": "2",
            "ram": "MemTotal: 4096",
            "disk": "/dev/sda1 40G",
            "error": "",
        },
        ssh_host="10.0.0.5",
    )
    assert facts.hostname == "db-01"
    assert facts.os_id == "ubuntu"
    assert facts.binaries == ["psql", "postgres"]
    assert facts.listening_ports == [5432, 22]
    assert facts.ssh_host == "10.0.0.5"

    incomplete = parse_host_facts_json({"hostname": ""}, ssh_host="10.0.0.8")
    raw = {
        "hostname": "Static hostname: live-db\n",
        "os": 'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04"\n',
        "binaries": "postgres=/usr/bin/postgres\npsql=/usr/bin/psql\n",
        "ports": "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n",
        "ips": "10.0.0.8 127.0.0.1\n",
    }
    merged = merge_facts_from_raw(incomplete, raw)
    assert merged.hostname == "live-db"
    assert merged.os_id == "ubuntu"
    assert "postgres" in merged.binaries
    assert 5432 in merged.listening_ports
    assert "10.0.0.8" in merged.ips


def test_parse_host_facts_json_string_lists():
    from auditor.host_facts import parse_host_facts_json

    facts = parse_host_facts_json(
        {"ips": "10.1.1.1, 10.1.1.2", "binaries": "docker nginx", "listening_ports": 80}
    )
    assert facts.ips == ["10.1.1.1", "10.1.1.2"]
    assert facts.binaries == ["docker", "nginx"]
    assert facts.listening_ports == [80]


def test_merge_facts_from_raw_ssh_error():
    from auditor.host_facts import HostFacts, merge_facts_from_raw

    facts = HostFacts()
    merge_facts_from_raw(facts, {"tool_1_ssh_run": "SSH error: connection refused"})
    assert "ssh error" in facts.error.lower()


def test_parse_os_and_software():
    os_id, ver, pretty = parse_os_release(
        'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nPRETTY_NAME="Ubuntu 22.04"\n'
    )
    assert os_id == "ubuntu"
    assert ver == "22.04"
    assert "Ubuntu" in pretty
    assert parse_binaries_present(
        "postgres=/usr/bin/postgres\npsql=\ndocker=/usr/bin/docker\n"
    ) == [
        "postgres",
        "docker",
    ]
    assert 5432 in parse_listening_ports("LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n")


def test_upsert_inventory(tmp_path: Path):
    path = tmp_path / "client" / "INVENTORY.md"
    facts = HostFacts(hostname="h1", ips=["1.2.3.4"], cpu="2", ram="1024", disk="/ 20G")
    upsert_inventory_md(
        path,
        client_name="Client",
        facts=facts,
        scope_text="Scope hosts",
        reachable_services=[{"name": "ssh", "status": "ok", "detail": "ok"}],
    )
    text = path.read_text(encoding="utf-8")
    assert "h1" in text
    assert "1.2.3.4" in text
    assert "ssh" in text


def test_resolve_client_inventory_found(tmp_path: Path):
    from auditor.host_facts import resolve_client_inventory

    path = tmp_path / "acme" / "INVENTORY.md"
    path.parent.mkdir(parents=True)
    path.write_text("# Scope\nhost-a\n", encoding="utf-8")
    found_path, text, found = resolve_client_inventory(tmp_path, "acme")
    assert found is True
    assert found_path == path
    assert "host-a" in text


def test_resolve_client_inventory_missing_no_example(tmp_path: Path):
    from auditor.host_facts import resolve_client_inventory

    (tmp_path / "INVENTORY.example.md").write_text("# Example only\n", encoding="utf-8")
    found_path, text, found = resolve_client_inventory(tmp_path, "missing_client")
    assert found is False
    assert found_path is not None
    assert "Example only" not in text
    assert "not found" in text.lower() or "No inventory" in text


def test_resolve_client_dir_case_insensitive(tmp_path: Path):
    from auditor.host_facts import resolve_client_dir

    (tmp_path / "TestCompany").mkdir()
    assert resolve_client_dir(tmp_path, "testcompany").name == "TestCompany"


def test_load_inventory_credentials(tmp_path: Path):
    from auditor.secrets_file import load_inventory_credentials

    client = tmp_path / "TestCompany"
    client.mkdir()
    (client / "INVENTORY.md").write_text(
        """
## Credentials & access

| Access | Host / URL | Port | Username | Password / Token | Database |
|--------|------------|------|----------|------------------|----------|
| SSH | 10.1.1.1 | 22 | auditor | | |
| PostgreSQL | 10.1.1.1 | 5432 | postgres | secret | app |
""",
        encoding="utf-8",
    )
    env: dict[str, str] = {"SSH_HOST": "old"}
    applied = load_inventory_credentials(
        tmp_path, "testcompany", environ=env, override_existing=True
    )
    assert applied["SSH_HOST"] == "10.1.1.1"
    assert env["SSH_HOST"] == "10.1.1.1"
    assert env["SSH_PORT"] == "22"
    assert env["PG_PASSWORD"] == "secret"
    assert env["PG_DATABASE"] == "app"

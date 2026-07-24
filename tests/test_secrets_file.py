"""Tests for secrets/connection.md loading."""

from pathlib import Path

from auditor.secrets_file import load_connection_secrets, _parse_env_text


def test_parse_env_fence():
    text = """# Connection

```env
SSH_HOST=db.example
PG_PASSWORD=s3cret
MCP_POSTGRES_COMMAND=npx
IGNORED_KEY=nope
```
"""
    parsed = _parse_env_text(text)
    assert parsed["SSH_HOST"] == "db.example"
    assert parsed["PG_PASSWORD"] == "s3cret"
    assert parsed["MCP_POSTGRES_COMMAND"] == "npx"
    assert "IGNORED_KEY" not in parsed


def test_parse_credentials_table():
    from auditor.secrets_file import parse_inventory_credentials

    text = """
## Credentials & access

| Access | Host / URL | Port | Username | Password / Token | Database |
|--------|------------|------|----------|------------------|----------|
| SSH | 10.200.29.79 | 22 | user | EDCrfv123 | |
| PostgreSQL | 10.200.29.79 | 5432 | hermes_ro | EDCrfv123 | test_1c |
"""
    parsed = parse_inventory_credentials(text)
    assert parsed["SSH_HOST"] == "10.200.29.79"
    assert parsed["SSH_PORT"] == "22"
    assert parsed["SSH_USER"] == "user"
    assert parsed["SSH_PASSWORD"] == "EDCrfv123"
    assert parsed["PG_HOST"] == "10.200.29.79"
    assert parsed["PG_PORT"] == "5432"
    assert parsed["PG_USER"] == "hermes_ro"
    assert parsed["PG_PASSWORD"] == "EDCrfv123"
    assert parsed["PG_DATABASE"] == "test_1c"


def test_list_inventory_ssh_targets_multi_host():
    from auditor.secrets_file import list_inventory_ssh_targets

    text = """
| Access | Host / URL | Port | Username | Password / Token | Database |
|--------|------------|------|----------|------------------|----------|
| SSH | 10.200.29.79 | 22 | user | EDCrfv123 | |
| PostgreSQL | 10.200.29.79 | 5432 | hermes_ro | EDCrfv123 | test_1c |
| 1C Ubuntu | 10.200.29.78 | 22 | hermes_ro | EDCrfv123 | |
"""
    targets = list_inventory_ssh_targets(text)
    hosts = [t.host for t in targets]
    assert hosts == ["10.200.29.79", "10.200.29.78"]
    assert targets[0].slug == "10.200.29.79"
    assert targets[1].user == "hermes_ro"


def test_parse_strict_host_key_in_extra():
    from auditor.secrets_file import parse_inventory_credentials

    text = """
| Access | Host / URL | Port | Username | Password / Token | Extra |
|--------|------------|------|----------|------------------|-------|
| SSH | 10.0.0.1 | 22 | user | secret | lab; strict_host_key=false |
"""
    parsed = parse_inventory_credentials(text)
    assert parsed["SSH_STRICT_HOST_KEY"] == "false"
    assert parsed["SSH_HOST"] == "10.0.0.1"


def test_load_connection_md(tmp_path: Path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "connection.md").write_text(
        """
```env
SSH_HOST=10.0.0.5
SSH_PORT=2222
PG_HOST=10.0.0.5
PG_PASSWORD=hidden
```
""",
        encoding="utf-8",
    )
    env: dict[str, str] = {}
    applied = load_connection_secrets(secrets, environ=env)
    assert applied["SSH_HOST"] == "10.0.0.5"
    assert env["PG_PASSWORD"] == "hidden"
    assert env["SSH_PORT"] == "2222"


def test_existing_env_wins(tmp_path: Path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "connection.md").write_text(
        "```env\nSSH_HOST=from-file\n```\n",
        encoding="utf-8",
    )
    env = {"SSH_HOST": "from-shell"}
    load_connection_secrets(secrets, environ=env)
    assert env["SSH_HOST"] == "from-shell"


def test_list_client_access_endpoints_keeps_unknown_service_rows(tmp_path: Path):
    from auditor.secrets_file import list_client_access_endpoints

    client = tmp_path / "acme"
    client.mkdir()
    (client / "INVENTORY.md").write_text(
        """
| Access | Host / URL | Port | Username | Password / Token | Extra |
|--------|------------|------|----------|------------------|-------|
| Router API | 10.1.2.3 | 8443 | | | |
| Legacy service | 10.1.2.4 | 9000 | | | |
| Weird label without port | 10.1.2.5 | | | | |
""",
        encoding="utf-8",
    )
    rows = list_client_access_endpoints(tmp_path, "acme")
    by_host = {row["host"]: row for row in rows}
    assert by_host["10.1.2.3"]["kind"] == "tcp"
    assert by_host["10.1.2.3"]["port"] == "8443"
    assert by_host["10.1.2.4"]["kind"] == "tcp"
    assert by_host["10.1.2.4"]["port"] == "9000"
    # Generic/unknown access label without explicit port is still retained.
    assert by_host["10.1.2.5"]["kind"] == "tcp"
    assert by_host["10.1.2.5"]["port"] == ""


def test_list_client_access_endpoints_snmp_default_port(tmp_path: Path):
    from auditor.secrets_file import list_client_access_endpoints

    client = tmp_path / "acme"
    client.mkdir()
    (client / "INVENTORY.md").write_text(
        """
| Access | Host / URL | Port | Username | Password / Token | Extra |
|--------|------------|------|----------|------------------|-------|
| SNMP | switch.local | | | | |
""",
        encoding="utf-8",
    )
    rows = list_client_access_endpoints(tmp_path, "acme")
    by_host = {row["host"]: row for row in rows}
    assert by_host["switch.local"]["kind"] == "snmp"
    assert by_host["switch.local"]["protocol"] == "snmp"
    assert by_host["switch.local"]["port"] == "161"

"""Tests for declarative ``mcps/registry.json`` loading and env injection."""

from pathlib import Path

import pytest

from auditor.config import Settings
from auditor.mcp_registry import (
    build_stdio_connection,
    credentials_ready,
    format_registry_markdown,
    load_mcp_registry,
)
from auditor.tools.mcp_client import get_mcp_tools, postgres_mcp_connection


def test_load_bundled_registry():
    registry = load_mcp_registry(Path("mcps"))
    assert registry.version == 1
    assert "postgres" in registry.servers
    pg = registry.servers["postgres"]
    assert pg.enabled
    assert pg.env_from == "inventory:pg"
    assert pg.curated_tools
    assert "postgres_cis" in pg.frameworks
    assert registry.servers["mysql"].enabled is False
    assert registry.servers["oracle"].enabled is False


def test_build_postgres_connection_injects_pg_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    registry_dir = tmp_path / "mcps"
    registry_dir.mkdir()
    (registry_dir / "registry.json").write_text(
        """
{
  "version": 1,
  "mcpServers": {
    "postgres": {
      "enabled": true,
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "mcp-postgres-server"],
      "envFrom": "inventory:pg",
      "curatedTools": true,
      "blockedTools": ["execute"]
    }
  }
}
""".strip(),
        encoding="utf-8",
    )
    settings = Settings(
        _env_file=None,
        mcps_dir=registry_dir,
        pg_host="10.1.2.3",
        pg_port=5432,
        pg_user="ro",
        pg_password="secret",
        pg_database="app",
    )
    conn = postgres_mcp_connection(settings)
    assert conn["transport"] == "stdio"
    assert conn["command"] == "npx"
    assert conn["args"] == ["-y", "mcp-postgres-server"]
    assert conn["env"]["PG_HOST"] == "10.1.2.3"
    assert conn["env"]["PG_PASSWORD"] == "secret"
    assert conn["env"]["PG_DATABASE"] == "app"


def test_registry_rejects_password_in_static_env(tmp_path: Path):
    registry_dir = tmp_path / "mcps"
    registry_dir.mkdir()
    (registry_dir / "registry.json").write_text(
        """
{
  "version": 1,
  "mcpServers": {
    "bad": {
      "enabled": true,
      "command": "npx",
      "args": ["-y", "x"],
      "env": {"MYSQL_PASSWORD": "nope"}
    }
  }
}
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must not contain secret"):
        load_mcp_registry(registry_dir)


def test_mysql_env_from_os(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "10.0.0.11")
    monkeypatch.setenv("MYSQL_PORT", "3306")
    monkeypatch.setenv("MYSQL_USER", "ro")
    monkeypatch.setenv("MYSQL_PASSWORD", "pw")
    monkeypatch.setenv("MYSQL_DATABASE", "app")
    monkeypatch.setenv("PATH", "/usr/bin")
    registry_dir = tmp_path / "mcps"
    registry_dir.mkdir()
    (registry_dir / "registry.json").write_text(
        """
{
  "version": 1,
  "mcpServers": {
    "mysql": {
      "enabled": true,
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "demo-mysql-mcp"],
      "envFrom": "inventory:mysql"
    }
  }
}
""".strip(),
        encoding="utf-8",
    )
    settings = Settings(_env_file=None, mcps_dir=registry_dir)
    registry = load_mcp_registry(registry_dir)
    spec = registry.get("mysql")
    assert spec is not None
    conn = build_stdio_connection(spec, settings)
    assert conn["env"]["MYSQL_HOST"] == "10.0.0.11"
    assert conn["env"]["MYSQL_PASSWORD"] == "pw"
    assert credentials_ready(spec, settings)


def test_format_registry_markdown_and_tools():
    settings = Settings(_env_file=None, mcps_dir=Path("mcps"))
    registry = load_mcp_registry(Path("mcps"))
    md = format_registry_markdown(registry, settings)
    assert "`postgres`" in md
    assert "inventory" in md.lower() or "Credentials" in md
    names = [t.name for t in get_mcp_tools()]
    assert "mcp_list_servers" in names
    assert "mcp_query" in names


def test_inventory_parses_mysql_oracle_kinds():
    from auditor.secrets_file import _parse_credentials_table

    text = """
| Access | Host | Port | Username | Password / Token | Database |
|--------|------|------|----------|------------------|----------|
| MySQL | 10.0.0.11 | 3306 | ro | secret | app |
| Oracle | 10.0.0.12 | 1521 | ro | secret | service=ORCL |
"""
    parsed = _parse_credentials_table(text)
    assert parsed["MYSQL_HOST"] == "10.0.0.11"
    assert parsed["MYSQL_DATABASE"] == "app"
    assert parsed["ORACLE_HOST"] == "10.0.0.12"
    assert parsed["ORACLE_SERVICE"] == "ORCL"

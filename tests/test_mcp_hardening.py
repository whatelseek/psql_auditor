"""MCP / config hardening: isError formatting, SQL gate, DATABASE_URL merge."""

from types import SimpleNamespace

from auditor.config import Settings
from auditor.tools.mcp_client import _format_mcp_result
from auditor.tools.postgres import is_readonly_sql
from auditor.tools.secrets import redact_secrets


def test_format_mcp_result_honors_is_error():
    result = SimpleNamespace(
        isError=True,
        content=[SimpleNamespace(text="relation missing")],
    )
    text = _format_mcp_result(result)
    assert text.startswith("MCP error:")
    assert "relation missing" in text


def test_format_mcp_result_success_unchanged():
    result = SimpleNamespace(
        isError=False,
        content=[SimpleNamespace(text="ssl | on")],
    )
    assert _format_mcp_result(result) == "ssl | on"


def test_readonly_allows_with_select():
    assert is_readonly_sql("WITH x AS (SELECT 1) SELECT * FROM x")


def test_readonly_blocks_multi_statement():
    assert not is_readonly_sql("SELECT 1; DELETE FROM t")


def test_redact_secrets_nested():
    data = redact_secrets({"host": "db", "password": "x", "nested": {"token": "y"}})
    assert data["password"] == "***REDACTED***"
    assert data["nested"]["token"] == "***REDACTED***"
    assert data["host"] == "db"


def test_database_url_fills_password_when_host_set():
    settings = Settings(
        _env_file=None,
        pg_host="db.example",
        pg_port=5432,
        pg_user="postgres",
        pg_password=None,
        pg_database="postgres",
        database_url="postgresql://audit:secret@db.example:5432/auditdb",
    )
    fields = settings.resolve_pg_fields()
    assert fields["host"] == "db.example"
    assert fields["password"] == "secret"
    # Explicit discrete defaults win for user/database when set via field defaults
    # that are in model_fields_set from constructor kwargs... pg_user was passed.
    assert fields["user"] == "postgres"


def test_database_url_fills_blanks_when_discrete_unset():
    settings = Settings(
        _env_file=None,
        database_url="postgresql://audit:secret@db.example:5433/auditdb",
    )
    fields = settings.resolve_pg_fields()
    assert fields["host"] == "db.example"
    assert fields["port"] == 5433
    assert fields["user"] == "audit"
    assert fields["password"] == "secret"
    assert fields["database"] == "auditdb"

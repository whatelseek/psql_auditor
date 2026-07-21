from auditor.config import Settings
from auditor.tools.mcp_client import (
    PostgresMcpSession,
    postgres_mcp_connection,
    rewrite_show_to_select,
)


def test_rewrite_show_setting():
    sql = rewrite_show_to_select("SHOW ssl;")
    assert sql.upper().startswith("SELECT")
    assert "pg_settings" in sql
    assert "ssl" in sql


def test_rewrite_show_all():
    sql = rewrite_show_to_select("SHOW ALL")
    assert "pg_settings" in sql
    assert "ORDER BY name" in sql


def test_leaves_select_unchanged():
    original = "SELECT rolname FROM pg_roles WHERE rolsuper"
    assert rewrite_show_to_select(original) == original


def test_pg_env_for_mcp_from_discrete_fields():
    settings = Settings(
        _env_file=None,
        pg_host="db.example",
        pg_port=5433,
        pg_user="auditor",
        pg_password="secret",
        pg_database="postgres",
        database_url=None,
    )
    env = settings.pg_env_for_mcp()
    assert env["PG_HOST"] == "db.example"
    assert env["PG_PORT"] == "5433"
    assert env["PG_USER"] == "auditor"
    assert env["PG_PASSWORD"] == "secret"
    assert env["PG_DATABASE"] == "postgres"


def test_pg_env_parses_database_url():
    settings = Settings(
        _env_file=None,
        database_url="postgresql://alice:s3cret@dbhost:6543/appdb",
        pg_host=None,
        pg_password=None,
    )
    env = settings.pg_env_for_mcp()
    assert env["PG_HOST"] == "dbhost"
    assert env["PG_PORT"] == "6543"
    assert env["PG_USER"] == "alice"
    assert env["PG_PASSWORD"] == "s3cret"
    assert env["PG_DATABASE"] == "appdb"


def test_postgres_mcp_connection_shape():
    settings = Settings(
        _env_file=None,
        mcp_postgres_command="npx",
        mcp_postgres_args="-y mcp-postgres-server",
        pg_host="db.example",
        pg_user="auditor",
        pg_password="secret",
        pg_database="postgres",
        database_url=None,
    )
    conn = postgres_mcp_connection(settings)
    assert conn["transport"] == "stdio"
    assert conn["command"] == "npx"
    assert conn["args"] == ["-y", "mcp-postgres-server"]
    assert conn["env"]["PG_HOST"] == "db.example"


async def test_session_call_tool_blocks_execute():
    session = PostgresMcpSession()
    result = await session.call_tool("execute", {"sql": "DELETE FROM t"})
    assert "MCP error" in result
    assert "disabled" in result.lower() or "execute" in result.lower()

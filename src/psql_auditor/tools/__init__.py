"""Auditor tools: SSH, PostgreSQL SQL, and MCP."""

from psql_auditor.tools.postgres import run_sql, get_postgres_tools
from psql_auditor.tools.ssh import ssh_run, ssh_read_file, get_ssh_tools
from psql_auditor.tools.mcp_client import mcp_call_tool, get_mcp_tools

__all__ = [
    "run_sql",
    "get_postgres_tools",
    "ssh_run",
    "ssh_read_file",
    "get_ssh_tools",
    "mcp_call_tool",
    "get_mcp_tools",
]

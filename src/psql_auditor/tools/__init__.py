"""Auditor tools: SSH, PostgreSQL SQL, and MCP.

This package exposes LangChain ``@tool`` callables that the assess-loop model
may invoke while evaluating checklist requirements:

* ``ssh_run`` / ``ssh_read_file`` — host-level inspection over SSH
* ``run_sql`` — read-only SQL against the configured database
* ``mcp_call_tool`` / ``mcp_list_tools`` — optional Postgres MCP server

``get_*_tools`` helpers return lists suitable for ``bind_tools`` / ``ToolNode``.
"""

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

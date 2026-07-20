"""Auditor tools: SSH host inspection and Postgres MCP (antonorlov).

Database queries go exclusively through ``mcp_client`` wrappers around
https://github.com/antonorlov/mcp-postgres-server. Direct asyncpg ``run_sql``
remains available for optional offline use but is not bound into the agent.
"""

from auditor.tools.mcp_client import (
    get_mcp_tools,
    mcp_connect_db,
    mcp_describe_table,
    mcp_list_schemas,
    mcp_list_tables,
    mcp_list_tools,
    mcp_query,
)
from auditor.tools.ssh import get_ssh_tools, ssh_read_file, ssh_run

__all__ = [
    "get_mcp_tools",
    "mcp_connect_db",
    "mcp_describe_table",
    "mcp_list_schemas",
    "mcp_list_tables",
    "mcp_list_tools",
    "mcp_query",
    "get_ssh_tools",
    "ssh_run",
    "ssh_read_file",
]

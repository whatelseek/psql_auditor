"""Auditor tools: SSH host inspection and Postgres via LangChain MCP.

Pipeline role:
    LangChain ``@tool`` callables bound into the evidence-gathering model during
    ``assess_parallel``. SSH covers host-level checks; MCP subprocesses handle
    read-only SQL against the audit target.

Submodules:
    * ``ssh`` — Remote shell commands and file reads over asyncssh.
    * ``mcp_client`` — Postgres via ``langchain-mcp-adapters`` and
      https://github.com/antonorlov/mcp-postgres-server (pooled stateful sessions).
    * ``postgres`` — Read-only SQL gate used by MCP wrappers.
    * ``secrets`` — Redact credentials before evidence/playbook persistence.

Re-exported entry points (see ``__all__``):
    ``get_ssh_tools``, ``get_mcp_tools``, and the individual ``ssh_*`` / ``mcp_*``
    tool functions.
"""

from auditor.tools.mcp_client import (
    get_mcp_tools,
    mcp_connect_db,
    mcp_describe_table,
    mcp_list_schemas,
    mcp_list_tables,
    mcp_list_tools,
    mcp_query,
    postgres_mcp_connection,
    reconnect_mcp_session,
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
    "postgres_mcp_connection",
    "reconnect_mcp_session",
    "get_ssh_tools",
    "ssh_run",
    "ssh_read_file",
]

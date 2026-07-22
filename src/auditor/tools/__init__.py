"""Auditor tools: SSH host inspection and Postgres/NetBox via LangChain MCP.

Pipeline role:
    LangChain ``@tool`` callables bound into the evidence-gathering model during
    ``assess_parallel``. SSH covers host-level checks; MCP subprocesses handle
    read-only SQL and CMDB lookups.

Submodules:
    * ``ssh`` — Remote shell commands and file reads over asyncssh.
    * ``mcp_client`` — Postgres via ``langchain-mcp-adapters`` and
      https://github.com/antonorlov/mcp-postgres-server (pooled stateful sessions).
    * ``netbox_mcp`` — NetBox CMDB via https://github.com/netboxlabs/netbox-mcp-server.
    * ``postgres`` — Read-only SQL gate used by MCP wrappers.
    * ``secrets`` — Redact credentials before evidence/playbook persistence.

Re-exported entry points (see ``__all__``):
    ``get_ssh_tools``, ``get_mcp_tools``, ``get_netbox_tools``, and the
    individual ``ssh_*`` / ``mcp_*`` / ``netbox_*`` tool functions.
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
from auditor.tools.netbox_mcp import (
    get_netbox_tools,
    netbox_get_changelogs,
    netbox_get_object_by_id,
    netbox_get_objects,
    reconnect_netbox_session,
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
    "get_netbox_tools",
    "netbox_get_objects",
    "netbox_get_object_by_id",
    "netbox_get_changelogs",
    "reconnect_netbox_session",
    "get_ssh_tools",
    "ssh_run",
    "ssh_read_file",
]

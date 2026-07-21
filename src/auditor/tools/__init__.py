"""Auditor tools: SSH host inspection and Postgres/NetBox via LangChain MCP.

Database queries go through ``mcp_client`` (``langchain-mcp-adapters`` +
https://github.com/antonorlov/mcp-postgres-server). CMDB lookups use
``netbox_mcp`` (https://github.com/netboxlabs/netbox-mcp-server).
"""

from auditor.tools.mcp_client import (
    get_mcp_pool,
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
    "get_mcp_pool",
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

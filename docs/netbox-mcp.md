# NetBox MCP (CMDB)

CMDB lookups use **[netboxlabs/netbox-mcp-server](https://github.com/netboxlabs/netbox-mcp-server)**
via [`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters)
(`MultiServerMCPClient` + **stateful** `client.session("netbox")`), same pattern as
Postgres MCP. See the official guide:
[LangChain MCP](https://docs.langchain.com/oss/python/langchain/mcp#stateful-sessions).

```text
Intake / it_audit
      │
      ▼
netbox_get_objects / netbox_get_object_by_id / netbox_get_changelogs
      │
      ▼
NetboxMcpSession  (process-wide, asyncio.Lock; single stdio worker)
      │
      ▼
MultiServerMCPClient.session("netbox")  (handle_tool_errors=True)
      │
      ▼
uv --directory /opt/netbox-mcp-server run netbox-mcp-server
      (NETBOX_URL + NETBOX_TOKEN; cloned into the agent image)
```

A **pool is not used** for NetBox: intake/drift calls are infrequent compared to
parallel `mcp_query` during Postgres CIS. One locked stateful session is enough.

Read-only. The auditor never writes devices back to NetBox.

The package is not on PyPI yet; the agent Dockerfile clones
`github.com/netboxlabs/netbox-mcp-server` to `/opt/netbox-mcp-server`.

## Secrets

In [`secrets/connection.md`](../secrets/connection.example.md):

```env
NETBOX_URL=https://netbox.example.com/
NETBOX_TOKEN=…
NETBOX_VERIFY_SSL=true
MCP_NETBOX_COMMAND=uv
MCP_NETBOX_ARGS=--directory /opt/netbox-mcp-server run netbox-mcp-server
```

Leave URL/token empty when the client has no CMDB; intake will use
[`inventory/INVENTORY.md`](../inventory/INVENTORY.example.md) instead.

## Intake field mapping

| Asked in chat | NetBox source |
|---------------|---------------|
| Hostname | `device.name` |
| IP | `primary_ip4` / `primary_ip6` |
| Subnet | IPAM prefix (when resolvable) |
| Owner | `tenant` / `role` / custom fields |
| Location | `site` / `location` |
| CPU / RAM / HDD | custom fields or inventory items (often absent) |
| Access port / method | custom fields (else unknown) |

Live SSH facts are compared to NetBox for hostname/IP **drift** in the report.

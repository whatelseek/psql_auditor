# Connection secrets (example)

Copy this file to `connection.md` in the same folder and fill in real values.
**Do not commit `connection.md`** — only this example may be in git.

The agent loads `secrets/connection.md` at startup (Docker mounts `./secrets` → `/app/secrets`).
These keys must **not** be set in `docker-compose.yml`.

```env
SSH_HOST=
SSH_PORT=22
SSH_USER=postgres
SSH_PRIVATE_KEY_PATH=
SSH_PASSWORD=
DATABASE_URL=
PG_HOST=
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=
PG_DATABASE=postgres
MCP_POSTGRES_COMMAND=npx
MCP_POSTGRES_ARGS=-y mcp-postgres-server
NETBOX_URL=
NETBOX_TOKEN=
NETBOX_VERIFY_SSL=true
MCP_NETBOX_COMMAND=uv
MCP_NETBOX_ARGS=--directory /opt/netbox-mcp-server run netbox-mcp-server
```

Optional (also supported if present):

```env
SSH_CONNECT_TIMEOUT=15
SSH_STRICT_HOST_KEY=true
```

Prefer mounting a private key via Compose (`SSH_KEY_HOST_PATH` → `/keys`) and set
`SSH_PRIVATE_KEY_PATH=/keys/id_ed25519` instead of `SSH_PASSWORD`.

NetBox MCP: [netboxlabs/netbox-mcp-server](https://github.com/netboxlabs/netbox-mcp-server)
(read-only). Leave `NETBOX_URL` / `NETBOX_TOKEN` empty when the client has no CMDB.
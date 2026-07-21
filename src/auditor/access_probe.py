"""Probe SSH / Postgres / WinRM reachability for intake step 3."""

from __future__ import annotations

from typing import Any

from auditor.config import Settings, get_settings


async def probe_access_services(settings: Settings | None = None) -> dict[str, Any]:
    """Return a structured list of reachable vs failed services."""
    settings = settings or get_settings()
    services: list[dict[str, Any]] = []

    # SSH
    ssh_detail = ""
    ssh_status = "failed"
    if not settings.ssh_host:
        ssh_status = "not_configured"
        ssh_detail = "SSH_HOST not set in secrets/connection.md"
    else:
        try:
            from auditor.tools.ssh import ssh_run

            result = str(
                await ssh_run.ainvoke({"command": "echo auditor_access_ok && hostname"})
            )
            if result.lower().startswith("ssh error"):
                ssh_status = "failed"
                ssh_detail = result[:500]
            else:
                ssh_status = "ok"
                ssh_detail = result[:500]
        except Exception as exc:  # noqa: BLE001
            ssh_status = "failed"
            ssh_detail = f"{type(exc).__name__}: {exc}"
    services.append({"name": "ssh", "status": ssh_status, "detail": ssh_detail})

    # PostgreSQL via MCP
    pg_status = "failed"
    pg_detail = ""
    fields = settings.resolve_pg_fields()
    if not fields.get("host"):
        pg_status = "not_configured"
        pg_detail = "PG_HOST / DATABASE_URL not set"
    else:
        try:
            from auditor.tools.mcp_client import mcp_query

            result = str(
                await mcp_query.ainvoke(
                    {"sql": "SELECT current_database() AS db, current_user AS usr"}
                )
            )
            if result.lower().startswith("mcp error"):
                pg_status = "failed"
                pg_detail = result[:500]
            else:
                pg_status = "ok"
                pg_detail = result[:500]
        except Exception as exc:  # noqa: BLE001
            pg_status = "failed"
            pg_detail = f"{type(exc).__name__}: {exc}"
    services.append({"name": "postgres_mcp", "status": pg_status, "detail": pg_detail})

    # WinRM — not implemented in this release
    services.append(
        {
            "name": "winrm",
            "status": "not_configured",
            "detail": "WinRM client not bundled; Windows targets use SSH/OpenSSH when available",
        }
    )

    return {
        "services": services,
        "any_ok": any(s["status"] == "ok" for s in services),
    }

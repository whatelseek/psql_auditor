"""Probe SSH, PostgreSQL, and WinRM reachability for pre-audit intake.

Runs during intake step 3 ("access verification") before the main audit graph
assesses checklist requirements. :func:`probe_access_services` performs lightweight
live checks against configured endpoints and returns a structured status dict
for the operator and for :func:`auditor.host_facts.upsert_inventory_md`.

Does not mutate audit state; results inform whether ``has_access`` can be set and
which tools (SSH, MCP Postgres) are expected to succeed during evidence gathering.
"""

from __future__ import annotations

from typing import Any

from auditor.config import Settings, get_settings


async def probe_access_services(settings: Settings | None = None) -> dict[str, Any]:
    """Probe configured access channels and return structured reachability results.

  Checks, in order:

  * **SSH** — runs ``echo auditor_access_ok && hostname`` via :mod:`auditor.tools.ssh`.
  * **PostgreSQL (MCP)** — runs ``SELECT current_database(), current_user`` via MCP.
  * **WinRM** — always reported as ``not_configured`` (not bundled in this release).

  Each service entry includes ``name``, ``status`` (``ok``, ``failed``,
  ``not_configured``), and a truncated ``detail`` string.

  Args:
      settings: Optional settings override; defaults to :func:`get_settings`.

  Returns:
      Dict with keys:

      * ``services``: list of per-service status dicts.
      * ``any_ok``: ``True`` if at least one service returned ``ok``.
  """
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

"""Probe SSH, PostgreSQL, and WinRM reachability for pre-audit intake.

Runs during intake step 3 ("access verification") before the main audit graph
assesses checklist requirements. :func:`probe_access_services` performs lightweight
live checks against configured endpoints and returns a structured status dict
for the operator and for :func:`auditor.host_facts.upsert_inventory_md`.

Does not mutate audit state; results inform whether ``has_access`` can be set and
which tools (SSH, MCP Postgres) are expected to succeed during evidence gathering.
"""

from __future__ import annotations

import asyncio
from typing import Any

from auditor.config import Settings
from auditor.runtime_target import effective_settings


async def probe_tcp_endpoint(
    host: str,
    port: int | str,
    *,
    timeout: float = 3.0,
) -> bool:
    """Return True when a TCP connect to ``host:port`` succeeds.

    Args:
        host: Hostname or IP.
        port: TCP port.
        timeout: Connect timeout in seconds.

    Returns:
        ``True`` when the socket connects; ``False`` on timeout/error.
    """
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return False
    if not host or port_i <= 0:
        return False
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port_i),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


async def probe_access_endpoints(
    endpoints: list[dict[str, str]],
    *,
    timeout: float = 3.0,
) -> list[dict[str, str]]:
    """Probe inventory Access endpoints and return status rows for intake step 3.

    Args:
        endpoints: Rows from :func:`~auditor.secrets_file.list_client_access_endpoints`.
        timeout: Per-endpoint TCP connect timeout.

    Returns:
        Rows with ``service``, ``host``, ``port``, ``status``
        (``accessible`` / ``not accessible``).
    """
    rows: list[dict[str, str]] = []
    for ep in endpoints:
        host = str(ep.get("host") or "").strip()
        port = str(ep.get("port") or "").strip()
        service = str(ep.get("service") or ep.get("kind") or "service").strip()
        ok = await probe_tcp_endpoint(host, port, timeout=timeout)
        rows.append(
            {
                "service": service,
                "host": host,
                "port": port,
                "kind": str(ep.get("kind") or "").strip(),
                "status": "accessible" if ok else "not accessible",
            }
        )
    return rows


async def probe_access_services(settings: Settings | None = None) -> dict[str, Any]:
    """Probe configured access channels and return structured reachability results.

  Checks, in order:

  * **SSH** — runs ``echo auditor_access_ok && hostname`` via :mod:`auditor.tools.ssh`.
  * **PostgreSQL (MCP)** — runs ``SELECT current_database(), current_user`` via MCP.
  * **WinRM** — runs a PowerShell hostname probe via :mod:`auditor.tools.winrm`.

  Each service entry includes ``name``, ``status`` (``ok``, ``failed``,
  ``not_configured``), and a truncated ``detail`` string.

  Args:
      settings: Optional settings override; defaults to
          :func:`~auditor.runtime_target.effective_settings`.

  Returns:
      Dict with keys:

      * ``services``: list of per-service status dicts.
      * ``any_ok``: ``True`` if at least one service returned ``ok``.
  """
    settings = settings or effective_settings()
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

    # WinRM (pywinrm)
    winrm_status = "failed"
    winrm_detail = ""
    if not settings.winrm_host:
        winrm_status = "not_configured"
        winrm_detail = "WINRM_HOST not set (add a WinRM Access row in inventory)"
    else:
        try:
            from auditor.tools.winrm import winrm_run

            result = str(
                await winrm_run.ainvoke(
                    {"command": "Write-Output 'auditor_access_ok'; hostname"}
                )
            )
            if result.lower().startswith("winrm error"):
                winrm_status = "failed"
                winrm_detail = result[:500]
            else:
                winrm_status = "ok"
                winrm_detail = result[:500]
        except Exception as exc:  # noqa: BLE001
            winrm_status = "failed"
            winrm_detail = f"{type(exc).__name__}: {exc}"
    services.append({"name": "winrm", "status": winrm_status, "detail": winrm_detail})

    return {
        "services": services,
        "any_ok": any(s["status"] == "ok" for s in services),
    }

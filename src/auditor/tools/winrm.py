"""WinRM tools for Windows host inspection (PowerShell over WinRM).

Uses ``pywinrm`` against inventory ``WINRM_*`` credentials (or run-scoped
overlays). Prefer these tools for Windows targets without OpenSSH; Linux
hosts continue to use :mod:`auditor.tools.ssh`.
"""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.tools import tool

from auditor.config import Settings
from auditor.runtime_target import effective_settings


def _winrm_endpoint(settings: Settings) -> str:
    """Build the WinRM endpoint URL from settings."""
    host = (settings.winrm_host or "").strip()
    if not host:
        raise ValueError(
            "WINRM_HOST is not configured. Add a WinRM row to inventory "
            "or set WINRM_HOST in secrets."
        )
    port = int(settings.winrm_port or (5986 if settings.winrm_use_ssl else 5985))
    scheme = "https" if settings.winrm_use_ssl else "http"
    return f"{scheme}://{host}:{port}/wsman"


def _winrm_session(settings: Settings) -> Any:
    """Create a ``pywinrm`` Session for the current target."""
    import winrm

    user = (settings.winrm_user or "").strip()
    password = settings.winrm_password or ""
    if not user:
        raise ValueError("WINRM_USER is not configured.")
    transport = (settings.winrm_transport or "ntlm").strip().lower() or "ntlm"
    return winrm.Session(
        _winrm_endpoint(settings),
        auth=(user, password),
        transport=transport,
        server_cert_validation="validate" if settings.winrm_verify_ssl else "ignore",
        operation_timeout_sec=int(settings.winrm_command_timeout or 30),
        read_timeout_sec=int(settings.winrm_command_timeout or 30) + 10,
    )


def _format_winrm_result(result: Any) -> str:
    """Format a pywinrm ``Response`` like SSH tool output."""
    status = getattr(result, "status_code", None)
    stdout = ""
    stderr = ""
    try:
        stdout = (result.std_out or b"").decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        stdout = str(getattr(result, "std_out", "") or "")
    try:
        stderr = (result.std_err or b"").decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        stderr = str(getattr(result, "std_err", "") or "")
    parts = [
        f"exit_code={status}",
        f"stdout:\n{stdout.strip()}",
    ]
    if stderr.strip():
        parts.append(f"stderr:\n{stderr.strip()}")
    return "\n".join(parts)


async def _run_ps(script: str, settings: Settings | None = None) -> str:
    """Run PowerShell on the WinRM target (thread offload; pywinrm is sync)."""
    settings = settings or effective_settings()
    try:

        def _call() -> str:
            session = _winrm_session(settings)
            return _format_winrm_result(session.run_ps(script))

        return await asyncio.to_thread(_call)
    except Exception as exc:  # noqa: BLE001
        return f"WinRM error: {type(exc).__name__}: {exc}"


async def _read_file(path: str, settings: Settings | None = None) -> str:
    """Read a remote Windows file via PowerShell (truncated)."""
    # Escape single quotes for PowerShell single-quoted string.
    escaped = (path or "").replace("'", "''")
    script = (
        f"$p = '{escaped}'; "
        "if (-not (Test-Path -LiteralPath $p)) { "
        "Write-Error \"missing: $p\"; exit 1 }; "
        "Get-Content -LiteralPath $p -TotalCount 4000 -ErrorAction Stop"
    )
    return await _run_ps(script, settings=settings)


@tool
async def winrm_run(command: str) -> str:
    """Run PowerShell on a Windows host over WinRM.

    Use for Windows CIS / IT checks when the inventory has a WinRM Access row
    (port 5985 HTTP or 5986 HTTPS). Prefer this over ssh_run for WinRM-only hosts.

    Examples: `hostname`, `Get-ComputerInfo`, `Get-Service`, `Get-NetTCPConnection`.

    Args:
        command: PowerShell script or command to execute.

    Returns:
        Formatted output (exit code, stdout, stderr) or ``WinRM error: …``.
    """
    return await _run_ps(command)


@tool
async def winrm_read_file(path: str) -> str:
    """Read a file on a Windows host over WinRM (first ~4000 lines).

    Args:
        path: Absolute Windows path (e.g. ``C:\\Windows\\System32\\drivers\\etc\\hosts``).

    Returns:
        File contents wrapped in the WinRM result format, or an error string.
    """
    return await _read_file(path)


def get_winrm_tools() -> list:
    """Return LangChain tools for WinRM / PowerShell host inspection."""
    return [winrm_run, winrm_read_file]

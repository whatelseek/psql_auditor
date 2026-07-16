"""SSH tools for host-level PostgreSQL audit checks.

Used for evidence that lives on the database host rather than inside SQL
catalogs: ``postgresql.conf``, ``pg_hba.conf``, package versions, listening
sockets, data-directory permissions, and similar.

Connection parameters come from ``Settings`` (``SSH_HOST``, ``SSH_USER``,
key/password, etc.). Errors are returned as strings so the agent can record
``status=error`` instead of crashing the graph.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import asyncssh
from langchain_core.tools import tool

from psql_auditor.config import Settings, get_settings


def _ssh_kwargs(settings: Settings) -> dict[str, Any]:
    """Build keyword arguments for ``asyncssh.connect``.

    Prefers private-key auth when ``ssh_private_key_path`` is set; otherwise
    falls back to password auth. ``known_hosts`` is disabled for lab/dev
    flexibility — tighten this for production bastions if needed.

    Args:
        settings: Application settings containing SSH target credentials.

    Returns:
        Dict suitable for ``asyncssh.connect(**kwargs)``.

    Raises:
        ValueError: If ``SSH_HOST`` is not configured.
        FileNotFoundError: If a configured private key path does not exist.
    """
    if not settings.ssh_host:
        raise ValueError(
            "SSH_HOST is not configured. Set SSH_HOST (and credentials) in the environment."
        )
    kwargs: dict[str, Any] = {
        "host": settings.ssh_host,
        "port": settings.ssh_port,
        "username": settings.ssh_user,
        "known_hosts": None,
        "connect_timeout": settings.ssh_connect_timeout,
    }
    if settings.ssh_private_key_path:
        key_path = Path(settings.ssh_private_key_path)
        if not key_path.exists():
            raise FileNotFoundError(f"SSH private key not found: {key_path}")
        kwargs["client_keys"] = [str(key_path)]
    elif settings.ssh_password:
        kwargs["password"] = settings.ssh_password
    return kwargs


async def _run_remote(command: str, settings: Settings | None = None) -> str:
    """Execute a shell command on the SSH target and format the result.

    Always captures stdout/stderr and exit code (``check=False``) so non-zero
    exits still return useful evidence to the model.

    Args:
        command: Remote shell command string.
        settings: Optional settings override; defaults to ``get_settings()``.

    Returns:
        Multi-line string with ``exit_code``, ``stdout``, and optional
        ``stderr``, or an ``SSH error: …`` line on connection failure.
    """
    settings = settings or get_settings()
    try:
        async with asyncssh.connect(**_ssh_kwargs(settings)) as conn:
            result = await conn.run(command, check=False)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            parts = [
                f"exit_code={result.exit_status}",
                f"stdout:\n{stdout.strip()}",
            ]
            if stderr.strip():
                parts.append(f"stderr:\n{stderr.strip()}")
            return "\n".join(parts)
    except Exception as exc:  # noqa: BLE001 — surface to agent as evidence
        return f"SSH error: {type(exc).__name__}: {exc}"


async def _read_remote_file(path: str, settings: Settings | None = None) -> str:
    """Read a remote file via SSH, truncated to 200 KiB.

    Uses ``head -c`` through the shell so permission errors appear clearly in
    stderr. Single quotes in ``path`` are escaped for POSIX shells.

    Args:
        path: Absolute (preferred) or relative path on the remote host.
        settings: Optional settings override.

    Returns:
        Same format as ``_run_remote`` (exit code + stdout/stderr).
    """
    settings = settings or get_settings()
    # Escape single quotes for safe inclusion in a single-quoted shell string.
    escaped = path.replace("'", "'\"'\"'")
    return await _run_remote(f"head -c 200000 -- '{escaped}'", settings=settings)


@tool
async def ssh_run(command: str) -> str:
    """Run a shell command on the PostgreSQL host over SSH.

    Use for inspecting packages, listening ports, file permissions, and config paths.
    Examples: `ss -lntp | grep 5432`, `ls -ld /var/lib/postgresql`, `psql --version`.

    Args:
        command: Shell command to execute on the remote host.

    Returns:
        Formatted command output (exit code, stdout, stderr) or an error string.
    """
    return await _run_remote(command)


@tool
async def ssh_read_file(path: str) -> str:
    """Read a file on the PostgreSQL host over SSH (truncated for large files).

    Use for postgresql.conf, pg_hba.conf, pg_ident.conf, and similar.

    Args:
        path: Remote filesystem path to read.

    Returns:
        File contents (truncated) wrapped in the SSH result format, or an error.
    """
    return await _read_remote_file(path)


def get_ssh_tools() -> list:
    """Return LangChain tools for SSH host inspection.

    Returns:
        ``[ssh_run, ssh_read_file]`` for binding into the assess model.
    """
    return [ssh_run, ssh_read_file]

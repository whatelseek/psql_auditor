"""SSH tools for host-level PostgreSQL audit checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import asyncssh
from langchain_core.tools import tool

from psql_auditor.config import Settings, get_settings


def _ssh_kwargs(settings: Settings) -> dict[str, Any]:
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
    settings = settings or get_settings()
    # Prefer cat via shell for permission-denied clarity; limit size.
    escaped = path.replace("'", "'\"'\"'")
    return await _run_remote(f"head -c 200000 -- '{escaped}'", settings=settings)


@tool
async def ssh_run(command: str) -> str:
    """Run a shell command on the PostgreSQL host over SSH.

    Use for inspecting packages, listening ports, file permissions, and config paths.
    Examples: `ss -lntp | grep 5432`, `ls -ld /var/lib/postgresql`, `psql --version`.
    """
    return await _run_remote(command)


@tool
async def ssh_read_file(path: str) -> str:
    """Read a file on the PostgreSQL host over SSH (truncated for large files).

    Use for postgresql.conf, pg_hba.conf, pg_ident.conf, and similar.
    """
    return await _read_remote_file(path)


def get_ssh_tools() -> list:
    return [ssh_run, ssh_read_file]

"""SSH tools for host-level PostgreSQL audit checks (TOOL-001).

Registered through :mod:`auditor.tool_registry`. Connection parameters come
from the active inventory/run context via
:func:`~auditor.runtime_target.effective_settings` (ContextVar overlay from
:func:`~auditor.secrets_file.bind_ssh_target`). Tools never accept credentials
as arguments.

Invocations produce a normalized :class:`~auditor.domain.tool_result.ToolResult`
(EVID-001/003) and enforce read-only policy, timeouts, and output limits
(EVID-002). LangChain wrappers remain string-compatible for existing audits.
"""

from __future__ import annotations

import hashlib
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncssh
from langchain_core.tools import tool

from auditor.config import Settings
from auditor.domain.tool_result import ToolProvenance, ToolResult, ToolTargetRef
from auditor.runtime_target import effective_settings
from auditor.tools.secrets import redact_secrets
from auditor.tools.ssh_policy import is_readonly_ssh_command, readonly_ssh_denial_reason

_SSH_RUN_VERSION = "1.0.0"
_SSH_READ_VERSION = "1.0.0"
_last_tool_result: ContextVar[ToolResult | None] = ContextVar("ssh_last_tool_result", default=None)


def take_last_tool_result() -> ToolResult | None:
    """Return and clear the ToolResult produced by the latest SSH adapter call."""
    result = _last_tool_result.get()
    _last_tool_result.set(None)
    return result


def _remember_tool_result(result: ToolResult) -> ToolResult:
    _last_tool_result.set(result)
    return result


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _command_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()[:16]


def _ssh_kwargs(settings: Settings) -> dict[str, Any]:
    """Build keyword arguments for ``asyncssh.connect``.

    Prefers private-key auth when ``ssh_private_key_path`` is set; otherwise
    falls back to password auth. Host keys are verified by default
    (``SSH_STRICT_HOST_KEY=true``); set ``SSH_STRICT_HOST_KEY=false`` for
    lab targets without a known_hosts entry.

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
        "connect_timeout": settings.ssh_connect_timeout,
    }
    if not settings.ssh_strict_host_key:
        kwargs["known_hosts"] = None
    if settings.ssh_private_key_path:
        key_path = Path(settings.ssh_private_key_path)
        if not key_path.exists():
            raise FileNotFoundError(f"SSH private key not found: {key_path}")
        kwargs["client_keys"] = [str(key_path)]
    elif settings.ssh_password:
        kwargs["password"] = settings.ssh_password
    return kwargs


def resolve_ssh_target(settings: Settings | None = None) -> ToolTargetRef:
    """Resolve secret-free SSH target identity from the active run context."""
    settings = settings or effective_settings()
    return ToolTargetRef(
        host=str(settings.ssh_host or ""),
        port=int(settings.ssh_port) if settings.ssh_port else None,
        username=str(settings.ssh_user or ""),
        transport="ssh",
        asset_id="",
        label=str(settings.ssh_host or ""),
    )


def _limit_output(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    truncated = raw[:max_bytes].decode("utf-8", errors="replace")
    return truncated + f"\n…[truncated at {max_bytes} bytes]"


def _format_remote_result(exit_status: int | None, stdout: str, stderr: str) -> str:
    parts = [
        f"exit_code={exit_status}",
        f"stdout:\n{stdout.strip()}",
    ]
    if stderr.strip():
        parts.append(f"stderr:\n{stderr.strip()}")
    return "\n".join(parts)


async def _run_remote_raw(
    command: str,
    settings: Settings,
    *,
    timeout_seconds: float,
) -> tuple[str, int | None, str | None, str]:
    """Execute remote command; return (formatted_output, exit_code, error, status)."""
    try:
        async with asyncssh.connect(**_ssh_kwargs(settings)) as conn:
            result = await conn.run(
                command,
                check=False,
                timeout=float(timeout_seconds),
            )
            stdout_raw = result.stdout or ""
            stderr_raw = result.stderr or ""
            stdout = (
                stdout_raw.decode("utf-8", errors="replace")
                if isinstance(stdout_raw, bytes)
                else stdout_raw
            )
            stderr = (
                stderr_raw.decode("utf-8", errors="replace")
                if isinstance(stderr_raw, bytes)
                else stderr_raw
            )
            return (
                _format_remote_result(result.exit_status, stdout, stderr),
                int(result.exit_status) if result.exit_status is not None else None,
                None,
                "ok",
            )
    except TimeoutError as exc:
        msg = f"SSH error: TimeoutError: command exceeded {timeout_seconds}s ({exc})"
        return msg, None, msg, "timeout"
    except Exception as exc:  # noqa: BLE001 — surface to agent as evidence
        msg = f"SSH error: {type(exc).__name__}: {exc}"
        return msg, None, msg, "error"


async def _run_remote(command: str, settings: Settings | None = None) -> str:
    """Execute a shell command on the SSH target and format the result.

    Always captures stdout/stderr and exit code (``check=False``) so non-zero
    exits still return useful evidence to the model.

    Args:
        command: Remote shell command string.
        settings: Optional settings override; defaults to
            :func:`~auditor.runtime_target.effective_settings`.

    Returns:
        Multi-line string with ``exit_code``, ``stdout``, and optional
        ``stderr``, or an ``SSH error: …`` line on connection failure.
    """
    settings = settings or effective_settings()
    timeout = float(settings.ssh_command_timeout or 30)
    output, _exit, _err, _status = await _run_remote_raw(command, settings, timeout_seconds=timeout)
    return output


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
    settings = settings or effective_settings()
    # Escape single quotes for safe inclusion in a single-quoted shell string.
    escaped = path.replace("'", "'\"'\"'")
    return await _run_remote(f"head -c 200000 -- '{escaped}'", settings=settings)


def _base_provenance(
    *,
    command: str,
    policy_decision: str,
    provenance: ToolProvenance | None,
) -> ToolProvenance:
    base = provenance or ToolProvenance()
    return ToolProvenance(
        client_id=base.client_id,
        audit_run_id=base.audit_run_id,
        framework_id=base.framework_id,
        requirement_id=base.requirement_id,
        requirement_title=base.requirement_title,
        asset_id=base.asset_id,
        source="tool_registry",
        tool_catalog_hash=base.tool_catalog_hash,
        capability_policy_hash=base.capability_policy_hash,
        policy_decision=policy_decision,
        command_hash=_command_hash(command),
    )


async def invoke_ssh_run(
    command: str,
    *,
    settings: Settings | None = None,
    timeout_seconds: int | None = None,
    max_output_bytes: int = 200_000,
    provenance: ToolProvenance | None = None,
    enforce_readonly: bool = True,
) -> ToolResult:
    """Registered SSH adapter: run a command and return a normalized ToolResult."""
    started = _utc_now_iso()
    settings = settings or effective_settings()
    target = resolve_ssh_target(settings)
    args = redact_secrets({"command": command})

    if not (settings.ssh_host or "").strip():
        finished = _utc_now_iso()
        err = "SSH target not resolved from inventory/run context (SSH_HOST empty)"
        return _remember_tool_result(
            ToolResult(
                status="unauthorized",
                output="",
                error=err,
                tool_id="ssh_run",
                tool_version=_SSH_RUN_VERSION,
                target=target,
                started_at=started,
                finished_at=finished,
                provenance=_base_provenance(
                    command=command or "",
                    policy_decision="deny_missing_target",
                    provenance=provenance,
                ),
                arguments=args,
            )
        )

    if enforce_readonly and not is_readonly_ssh_command(command):
        finished = _utc_now_iso()
        reason = readonly_ssh_denial_reason(command) or "not read-only"
        err = f"SSH command denied by read-only policy: {reason}"
        return _remember_tool_result(
            ToolResult(
                status="denied",
                output="",
                error=err,
                tool_id="ssh_run",
                tool_version=_SSH_RUN_VERSION,
                target=target,
                started_at=started,
                finished_at=finished,
                provenance=_base_provenance(
                    command=command,
                    policy_decision="deny_readonly",
                    provenance=provenance,
                ),
                arguments=args,
            )
        )

    timeout = float(
        timeout_seconds if timeout_seconds is not None else (settings.ssh_command_timeout or 30)
    )
    output, exit_code, error, status = await _run_remote_raw(
        command, settings, timeout_seconds=timeout
    )
    output = _limit_output(output, max_output_bytes)
    finished = _utc_now_iso()
    return _remember_tool_result(
        ToolResult(
            status=status,  # type: ignore[arg-type]
            output=output,
            error=error,
            tool_id="ssh_run",
            tool_version=_SSH_RUN_VERSION,
            target=target,
            started_at=started,
            finished_at=finished,
            provenance=_base_provenance(
                command=command,
                policy_decision="allow",
                provenance=provenance,
            ),
            exit_code=exit_code,
            arguments=args,
        )
    )


async def invoke_ssh_read_file(
    path: str,
    *,
    settings: Settings | None = None,
    timeout_seconds: int | None = None,
    max_output_bytes: int = 200_000,
    provenance: ToolProvenance | None = None,
    enforce_readonly: bool = True,
) -> ToolResult:
    """Registered SSH adapter: read a remote file via bounded ``head -c``."""
    escaped = (path or "").replace("'", "'\"'\"'")
    command = f"head -c {int(max_output_bytes)} -- '{escaped}'"
    # File reads are inherently read-oriented; still run through ssh_run policy.
    result = await invoke_ssh_run(
        command,
        settings=settings,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        provenance=provenance,
        enforce_readonly=enforce_readonly,
    )
    args = redact_secrets({"path": path})
    return _remember_tool_result(
        ToolResult(
            status=result.status,
            output=result.output,
            error=result.error,
            tool_id="ssh_read_file",
            tool_version=_SSH_READ_VERSION,
            target=result.target,
            started_at=result.started_at,
            finished_at=result.finished_at,
            provenance=result.provenance,
            exit_code=result.exit_code,
            arguments=args,
        )
    )


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
    result = await invoke_ssh_run(command)
    return result.to_llm_text()


@tool
async def ssh_read_file(path: str) -> str:
    """Read a file on the PostgreSQL host over SSH (truncated for large files).

    Use for postgresql.conf, pg_hba.conf, pg_ident.conf, and similar.

    Args:
        path: Remote filesystem path to read.

    Returns:
        File contents (truncated) wrapped in the SSH result format, or an error.
    """
    result = await invoke_ssh_read_file(path)
    return result.to_llm_text()


def get_ssh_tools() -> list:
    """Return LangChain tools for SSH host inspection.

    Prefer :meth:`auditor.tool_registry.ToolRegistry.bindable_langchain_tools`
    for policy-aware binding. This helper remains for compatibility and tests.

    Returns:
        A list containing ``ssh_run`` and ``ssh_read_file``, suitable for
        binding into the evidence-gathering chat model via ``bind_tools``.
    """
    return [ssh_run, ssh_read_file]

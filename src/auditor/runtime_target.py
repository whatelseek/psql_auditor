"""Run-scoped SSH / WinRM / PostgreSQL credential overlays (concurrent-audit safe).

Process-global ``os.environ`` / cached :func:`~auditor.config.get_settings` cannot
isolate two audits aimed at different hosts. This module keeps an optional
:class:`RuntimeTarget` in a :class:`~contextvars.ContextVar` so each asyncio task
(and nested tool call) sees its own SSH/WinRM/PG credentials via
:func:`effective_settings`.

Application-owned base settings are also task-scoped via
:func:`bind_app_settings` so concurrent FastAPI apps do not share a cached
settings object. Credential overlays apply on top of that base.

``bind_ssh_target`` / :func:`bind_runtime_credentials` set the overlay for a
``with`` block. Prefer these over mutating ``os.environ`` in request handlers.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
from typing import Iterator, Mapping

from auditor.config import Settings, get_settings

_runtime_target: ContextVar["RuntimeTarget | None"] = ContextVar(
    "auditor_runtime_target",
    default=None,
)

_app_settings: ContextVar[Settings | None] = ContextVar(
    "auditor_app_settings",
    default=None,
)


def _truthy(value: str | bool | None, *, default: bool | None = None) -> bool | None:
    """Parse a loose bool from inventory / env text.

    Args:
        value: Raw string, bool, or ``None``.
        default: Returned when ``value`` is empty/None.

    Returns:
        Parsed bool, or ``default`` when the value is blank.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


@dataclass(frozen=True, slots=True)
class RuntimeTarget:
    """Optional per-run overlays for SSH, WinRM, and PostgreSQL MCP credentials."""

    ssh_host: str | None = None
    ssh_port: int | None = None
    ssh_user: str | None = None
    ssh_password: str | None = None
    ssh_private_key_path: str | None = None
    ssh_strict_host_key: bool | None = None
    winrm_host: str | None = None
    winrm_port: int | None = None
    winrm_user: str | None = None
    winrm_password: str | None = None
    winrm_transport: str | None = None
    winrm_use_ssl: bool | None = None
    winrm_verify_ssl: bool | None = None
    pg_host: str | None = None
    pg_port: int | None = None
    pg_user: str | None = None
    pg_password: str | None = None
    pg_database: str | None = None
    database_url: str | None = None

    def merge(self, other: "RuntimeTarget") -> "RuntimeTarget":
        """Return a copy with non-``None`` fields from ``other`` winning."""
        updates = {
            field: getattr(other, field)
            for field in RuntimeTarget.__dataclass_fields__
            if getattr(other, field) is not None
        }
        return replace(self, **updates) if updates else self

    def pg_fingerprint(self) -> str:
        """Stable key for MCP pool session affinity (host/user/db/port)."""
        return "|".join(
            [
                self.pg_host or "",
                str(self.pg_port or ""),
                self.pg_user or "",
                self.pg_database or "",
                # Include password so credential rotation forces reconnect.
                self.pg_password or "",
                self.database_url or "",
            ]
        )


def get_runtime_target() -> RuntimeTarget | None:
    """Return the current ContextVar overlay, or ``None`` when unbound."""
    return _runtime_target.get()


def get_app_settings() -> Settings | None:
    """Return the application-bound settings snapshot, or ``None`` when unbound."""
    return _app_settings.get()


@contextmanager
def bind_app_settings(settings: Settings) -> Iterator[Settings]:
    """Bind the application settings snapshot for the current task."""
    token = _app_settings.set(settings)
    try:
        yield settings
    finally:
        _app_settings.reset(token)


def _set_runtime_target(target: RuntimeTarget | None) -> Token:
    """Push ``target`` onto the ContextVar; return a reset token."""
    return _runtime_target.set(target)


def runtime_target_from_env_map(creds: Mapping[str, str]) -> RuntimeTarget:
    """Build a :class:`RuntimeTarget` from ``SSH_*`` / ``WINRM_*`` / ``PG_*`` keys.

    Args:
        creds: Credential mapping (inventory parse or connection.md keys).

    Returns:
        Overlay with only keys present in ``creds`` populated.
    """
    port: int | None = None
    if creds.get("SSH_PORT"):
        try:
            port = int(str(creds["SSH_PORT"]).strip())
        except ValueError:
            port = None
    pg_port: int | None = None
    if creds.get("PG_PORT"):
        try:
            pg_port = int(str(creds["PG_PORT"]).strip())
        except ValueError:
            pg_port = None
    winrm_port: int | None = None
    if creds.get("WINRM_PORT"):
        try:
            winrm_port = int(str(creds["WINRM_PORT"]).strip())
        except ValueError:
            winrm_port = None

    strict = _truthy(creds.get("SSH_STRICT_HOST_KEY"))
    use_ssl = _truthy(creds.get("WINRM_USE_SSL"))
    verify_ssl = _truthy(creds.get("WINRM_VERIFY_SSL"))
    return RuntimeTarget(
        ssh_host=creds.get("SSH_HOST") or None,
        ssh_port=port,
        ssh_user=creds.get("SSH_USER") or None,
        ssh_password=creds.get("SSH_PASSWORD") or None,
        ssh_private_key_path=creds.get("SSH_PRIVATE_KEY_PATH") or None,
        ssh_strict_host_key=strict,
        winrm_host=creds.get("WINRM_HOST") or None,
        winrm_port=winrm_port,
        winrm_user=creds.get("WINRM_USER") or None,
        winrm_password=creds.get("WINRM_PASSWORD") or None,
        winrm_transport=creds.get("WINRM_TRANSPORT") or None,
        winrm_use_ssl=use_ssl,
        winrm_verify_ssl=verify_ssl,
        pg_host=creds.get("PG_HOST") or None,
        pg_port=pg_port,
        pg_user=creds.get("PG_USER") or None,
        pg_password=creds.get("PG_PASSWORD") or None,
        pg_database=creds.get("PG_DATABASE") or None,
        database_url=creds.get("DATABASE_URL") or None,
    )


def runtime_target_from_ssh(
    *,
    host: str,
    port: str | int = "22",
    user: str = "",
    password: str = "",
    private_key_path: str = "",
    strict_host_key: str | bool = "",
) -> RuntimeTarget:
    """Build an SSH-only overlay (PostgreSQL / WinRM fields left unset)."""
    try:
        ssh_port = int(str(port or "22").strip() or "22")
    except ValueError:
        ssh_port = 22
    return RuntimeTarget(
        ssh_host=host or None,
        ssh_port=ssh_port,
        ssh_user=user or None,
        ssh_password=password or None,
        ssh_private_key_path=private_key_path or None,
        # Inventory omits the flag by default; match legacy AsyncsshTransport
        # (strict host-key checks are opt-in via inventory notes).
        ssh_strict_host_key=_truthy(strict_host_key, default=False),
    )


def runtime_target_from_winrm(
    *,
    host: str,
    port: str | int = "5985",
    user: str = "",
    password: str = "",
    transport: str = "ntlm",
    use_ssl: str | bool = "",
    verify_ssl: str | bool = "",
) -> RuntimeTarget:
    """Build a WinRM-only overlay."""
    try:
        winrm_port = int(str(port or "5985").strip() or "5985")
    except ValueError:
        winrm_port = 5985
    return RuntimeTarget(
        winrm_host=host or None,
        winrm_port=winrm_port,
        winrm_user=user or None,
        winrm_password=password or None,
        winrm_transport=(transport or "ntlm").strip() or "ntlm",
        winrm_use_ssl=_truthy(use_ssl, default=winrm_port == 5986),
        winrm_verify_ssl=_truthy(verify_ssl, default=True),
    )


def effective_settings(base: Settings | None = None) -> Settings:
    """Return ``base`` settings with the current run-scoped credential overlay applied.

    Args:
        base: Settings to overlay; defaults to the application-bound
            snapshot from :func:`bind_app_settings`, then legacy
            :func:`~auditor.config.get_settings`.

    Returns:
        A ``model_copy`` when an overlay is active; otherwise ``base`` unchanged.
    """
    settings = base or get_app_settings() or get_settings()
    overlay = get_runtime_target()
    if overlay is None:
        return settings
    updates: dict[str, object] = {}
    if overlay.ssh_host is not None:
        updates["ssh_host"] = overlay.ssh_host
    if overlay.ssh_port is not None:
        updates["ssh_port"] = overlay.ssh_port
    if overlay.ssh_user is not None:
        updates["ssh_user"] = overlay.ssh_user
    if overlay.ssh_password is not None:
        updates["ssh_password"] = overlay.ssh_password
    if overlay.ssh_private_key_path is not None:
        updates["ssh_private_key_path"] = overlay.ssh_private_key_path
    if overlay.ssh_strict_host_key is not None:
        updates["ssh_strict_host_key"] = overlay.ssh_strict_host_key
    if overlay.winrm_host is not None:
        updates["winrm_host"] = overlay.winrm_host
    if overlay.winrm_port is not None:
        updates["winrm_port"] = overlay.winrm_port
    if overlay.winrm_user is not None:
        updates["winrm_user"] = overlay.winrm_user
    if overlay.winrm_password is not None:
        updates["winrm_password"] = overlay.winrm_password
    if overlay.winrm_transport is not None:
        updates["winrm_transport"] = overlay.winrm_transport
    if overlay.winrm_use_ssl is not None:
        updates["winrm_use_ssl"] = overlay.winrm_use_ssl
    if overlay.winrm_verify_ssl is not None:
        updates["winrm_verify_ssl"] = overlay.winrm_verify_ssl
    if overlay.pg_host is not None:
        updates["pg_host"] = overlay.pg_host
    if overlay.pg_port is not None:
        updates["pg_port"] = overlay.pg_port
    if overlay.pg_user is not None:
        updates["pg_user"] = overlay.pg_user
    if overlay.pg_password is not None:
        updates["pg_password"] = overlay.pg_password
    if overlay.pg_database is not None:
        updates["pg_database"] = overlay.pg_database
    if overlay.database_url is not None:
        updates["database_url"] = overlay.database_url
    return settings.model_copy(update=updates) if updates else settings


def pg_fingerprint(settings: Settings) -> str:
    """Fingerprint PostgreSQL target credentials for MCP session affinity."""
    fields = settings.resolve_pg_fields()
    return "|".join(
        [
            str(fields.get("host") or ""),
            str(fields.get("port") or ""),
            str(fields.get("user") or ""),
            str(fields.get("database") or ""),
            str(fields.get("password") or ""),
            settings.database_url or "",
        ]
    )


@contextmanager
def bind_runtime_target(overlay: RuntimeTarget) -> Iterator[RuntimeTarget]:
    """Merge ``overlay`` onto the current ContextVar target for the block.

    Nested binds compose: SSH bind inside a client-credentials bind keeps PG
    fields from the outer overlay.
    """
    current = get_runtime_target()
    merged = overlay if current is None else current.merge(overlay)
    token = _set_runtime_target(merged)
    try:
        yield merged
    finally:
        _runtime_target.reset(token)


@contextmanager
def bind_runtime_credentials(creds: Mapping[str, str]) -> Iterator[RuntimeTarget]:
    """Bind SSH/WinRM/PG overlays from an inventory/env credential mapping."""
    with bind_runtime_target(runtime_target_from_env_map(creds)) as bound:
        yield bound

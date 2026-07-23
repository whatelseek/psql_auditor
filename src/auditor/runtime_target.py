"""Run-scoped SSH/PostgreSQL credential overlays (concurrent-audit safe).

Process-global ``os.environ`` / cached :func:`~auditor.config.get_settings` cannot
isolate two audits aimed at different hosts. This module keeps an optional
:class:`RuntimeTarget` in a :class:`~contextvars.ContextVar` so each asyncio task
(and nested tool call) sees its own SSH/PG credentials via
:func:`effective_settings`.

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
    """Optional per-run overlays for SSH and PostgreSQL MCP credentials."""

    ssh_host: str | None = None
    ssh_port: int | None = None
    ssh_user: str | None = None
    ssh_password: str | None = None
    ssh_private_key_path: str | None = None
    ssh_strict_host_key: bool | None = None
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


def _set_runtime_target(target: RuntimeTarget | None) -> Token:
    """Push ``target`` onto the ContextVar; return a reset token."""
    return _runtime_target.set(target)


def runtime_target_from_env_map(creds: Mapping[str, str]) -> RuntimeTarget:
    """Build a :class:`RuntimeTarget` from ``SSH_*`` / ``PG_*`` / ``DATABASE_URL`` keys.

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

    strict = _truthy(creds.get("SSH_STRICT_HOST_KEY"))
    return RuntimeTarget(
        ssh_host=creds.get("SSH_HOST") or None,
        ssh_port=port,
        ssh_user=creds.get("SSH_USER") or None,
        ssh_password=creds.get("SSH_PASSWORD") or None,
        ssh_private_key_path=creds.get("SSH_PRIVATE_KEY_PATH") or None,
        ssh_strict_host_key=strict,
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
    """Build an SSH-only overlay (PostgreSQL fields left unset)."""
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
        ssh_strict_host_key=_truthy(strict_host_key),
    )


def effective_settings(base: Settings | None = None) -> Settings:
    """Return ``base`` settings with the current run-scoped credential overlay applied.

    Args:
        base: Settings to overlay; defaults to process :func:`~auditor.config.get_settings`.

    Returns:
        A ``model_copy`` when an overlay is active; otherwise ``base`` unchanged.
    """
    settings = base or get_settings()
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
    """Bind SSH/PG overlays from an inventory/env credential mapping."""
    with bind_runtime_target(runtime_target_from_env_map(creds)) as bound:
        yield bound

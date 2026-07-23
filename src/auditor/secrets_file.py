"""Load connection credentials from ``secrets/*.md`` (not from Compose).

This module parses **Markdown credential tables** and fenced ``KEY=VALUE`` blocks
from operator-maintained secret files. It loads SSH and PostgreSQL
settings into the process environment without requiring them in ``docker-compose``.

Pipeline role:
    Called at startup and during multi-host discovery to bind SSH targets,
    probe CMDB/Postgres access, and supply inventory rows for follow-up runs.
    Default :func:`bind_ssh_target` uses a run-scoped ContextVar (see
    :mod:`auditor.runtime_target`) so concurrent audits do not clobber
    ``os.environ``.

Key entry points:
    :func:`load_connection_secrets` — global ``secrets/connection.md``.
    :func:`load_inventory_credentials` — per-client ``INVENTORY.md`` into env.
    :func:`read_client_credentials` — parse client inventory without mutating env.
    :func:`list_client_ssh_targets` / :func:`bind_ssh_target` — multi-host SSH.
    :class:`InventorySshTarget` — one SSH-capable inventory row.
"""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Keys that live only under secrets/ — never required in docker-compose.yml.
_SECRET_ENV_KEYS = frozenset(
    {
        "SSH_HOST",
        "SSH_PORT",
        "SSH_USER",
        "SSH_PRIVATE_KEY_PATH",
        "SSH_PASSWORD",
        "SSH_CONNECT_TIMEOUT",
        "SSH_STRICT_HOST_KEY",
        "DATABASE_URL",
        "PG_HOST",
        "PG_PORT",
        "PG_USER",
        "PG_PASSWORD",
        "PG_DATABASE",
        "MCP_POSTGRES_COMMAND",
        "MCP_POSTGRES_ARGS",
    }
)

_ENV_LINE = re.compile(
    r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$",
)

_FENCE = re.compile(
    r"```(?:env|dotenv|bash|sh)?\s*\n(.*?)```",
    re.IGNORECASE | re.DOTALL,
)

_TABLE_ROW = re.compile(r"^\|(.+)\|$")
_EXTRA_KV = re.compile(
    r"(?P<key>database|db|service|sid|service_name|key|private_key|ssh_key|path|"
    r"strict_host_key|ssh_strict_host_key)\s*=\s*(?P<val>\S+)",
    re.IGNORECASE,
)


def _cell(raw: str) -> str:
    """Strip whitespace and backticks from a Markdown table cell.

    Args:
        raw: Raw cell text from a pipe table row.

    Returns:
        Trimmed cell value.
    """
    return (raw or "").strip().strip("`")


def _norm_header(cell: str) -> str:
    """Normalize a table header to lowercase alphanumeric key for column lookup.

    Args:
        cell: Header cell text.

    Returns:
        Collapsed lowercase key (e.g. ``"Host / URL"`` → ``hosturl``).
    """
    return re.sub(r"[^a-z0-9]+", "", (cell or "").lower())


def _parse_extra(extra: str) -> dict[str, str]:
    """Parse ``Extra`` cell: ``database=…``, ``service=…``, ``key=/path``, …."""
    text = (extra or "").strip()
    out: dict[str, str] = {}
    if not text:
        return out
    for match in _EXTRA_KV.finditer(text):
        key = match.group("key").lower()
        val = match.group("val").strip().strip("'\"")
        if key in {"database", "db"}:
            out["database"] = val
        elif key in {"service", "sid", "service_name"}:
            out["service"] = val
        elif key in {"key", "private_key", "ssh_key", "path"}:
            out["key"] = val
        elif key in {"strict_host_key", "ssh_strict_host_key"}:
            out["strict_host_key"] = val
    if (
        "database" not in out
        and "service" not in out
        and "key" not in out
        and "strict_host_key" not in out
        and "=" not in text
    ):
        # Bare value in Extra for PostgreSQL rows → database name
        out["bare"] = text.strip("'\"")
    return out


def _access_kind(label: str) -> str | None:
    """Map an inventory ``Access`` column label to a credential kind.

    Args:
        label: Access/service type cell (e.g. ``SSH``, ``PostgreSQL``, ``MySQL``).

    Returns:
        ``ssh`` / ``pg`` / ``mysql`` / ``oracle``, or ``None`` when unrecognized.
    """
    low = (label or "").strip().lower()
    if not low:
        return None
    if low in {"ssh", "sftp", "os", "host"}:
        return "ssh"
    # OS / app host rows (e.g. "1C Ubuntu") that use SSH credentials
    if any(
        tok in low
        for tok in (
            "ubuntu",
            "debian",
            "centos",
            "rhel",
            "linux",
            "windows",
            "winrm",
        )
    ):
        return "ssh"
    if low.startswith("postgres") or low in {"pg", "psql", "database", "db"}:
        return "pg"
    if low.startswith("mysql") or low in {"mariadb", "maria"}:
        return "mysql"
    if low.startswith("oracle") or low in {"ora", "oracledb"}:
        return "oracle"
    return None


def _parse_credentials_table(text: str) -> dict[str, str]:
    """Parse a Markdown credentials table (Access / Host / Port / User / Secret)."""
    lines = (text or "").splitlines()
    header_idx = -1
    headers: list[str] = []
    for i, line in enumerate(lines):
        match = _TABLE_ROW.match(line.strip())
        if not match:
            continue
        cells = [_cell(c) for c in match.group(1).split("|")]
        norms = [_norm_header(c) for c in cells]
        if any(h in {"access", "service", "type"} for h in norms) and any(
            h in {"host", "hosturl", "url", "endpoint"} for h in norms
        ):
            header_idx = i
            headers = norms
            break
    if header_idx < 0:
        return {}

    def col(*aliases: str) -> int | None:
        """Return the first matching header column index, or None.

        Args:
            *aliases: Normalized header names to look up in order of preference.

        Returns:
            Zero-based column index, or ``None`` when none of the aliases exist.
        """
        for alias in aliases:
            if alias in headers:
                return headers.index(alias)
        return None

    i_access = col("access", "service", "type")
    i_host = col("hosturl", "host", "url", "endpoint", "address")
    i_port = col("port", "accessport", "tcpport")
    i_user = col("username", "user", "login")
    i_secret = col("passwordtoken", "password", "token", "secret", "passwd")
    i_extra = col("extra", "database", "notes", "path", "options")
    if i_access is None or i_host is None:
        return {}

    out: dict[str, str] = {}
    for line in lines[header_idx + 1 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if out:
                break
            continue
        # Skip separator rows: |---|---|
        if re.match(r"^\|[\s|:-]+\|$", stripped):
            continue
        cells = [_cell(c) for c in stripped.strip("|").split("|")]
        if len(cells) < len(headers):
            cells.extend([""] * (len(headers) - len(cells)))
        kind = _access_kind(cells[i_access] if i_access < len(cells) else "")
        if kind is None:
            continue
        host = cells[i_host] if i_host < len(cells) else ""
        port = cells[i_port] if i_port is not None and i_port < len(cells) else ""
        user = cells[i_user] if i_user is not None and i_user < len(cells) else ""
        secret = (
            cells[i_secret] if i_secret is not None and i_secret < len(cells) else ""
        )
        extra_raw = (
            cells[i_extra] if i_extra is not None and i_extra < len(cells) else ""
        )
        extra = _parse_extra(extra_raw)

        if kind == "ssh":
            # First SSH row wins for process-wide defaults (access probe).
            # Multi-host discovery uses list_inventory_ssh_targets separately.
            if host and "SSH_HOST" not in out:
                out["SSH_HOST"] = host
            if port and "SSH_PORT" not in out:
                out["SSH_PORT"] = port
            if user and "SSH_USER" not in out:
                out["SSH_USER"] = user
            if secret and "SSH_PASSWORD" not in out:
                out["SSH_PASSWORD"] = secret
            key_path = extra.get("key")
            if key_path and "SSH_PRIVATE_KEY_PATH" not in out:
                out["SSH_PRIVATE_KEY_PATH"] = key_path
            if (
                extra.get("strict_host_key") is not None
                and "SSH_STRICT_HOST_KEY" not in out
            ):
                out["SSH_STRICT_HOST_KEY"] = extra["strict_host_key"]
        elif kind == "pg":
            if host:
                out["PG_HOST"] = host
            if port:
                out["PG_PORT"] = port
            if user:
                out["PG_USER"] = user
            if secret:
                out["PG_PASSWORD"] = secret
            db = extra.get("database") or ""
            if not db and i_extra is not None and headers[i_extra] in {
                "database",
                "db",
            }:
                db = extra_raw
            if not db:
                db = extra.get("bare") or ""
            if db:
                out["PG_DATABASE"] = db
        elif kind == "mysql":
            if host:
                out["MYSQL_HOST"] = host
            if port:
                out["MYSQL_PORT"] = port
            if user:
                out["MYSQL_USER"] = user
            if secret:
                out["MYSQL_PASSWORD"] = secret
            db = extra.get("database") or extra.get("bare") or ""
            if not db and i_extra is not None and headers[i_extra] in {
                "database",
                "db",
            }:
                db = extra_raw
            if db:
                out["MYSQL_DATABASE"] = db
        elif kind == "oracle":
            if host:
                out["ORACLE_HOST"] = host
            if port:
                out["ORACLE_PORT"] = port
            if user:
                out["ORACLE_USER"] = user
            if secret:
                out["ORACLE_PASSWORD"] = secret
            svc = (
                extra.get("service")
                or extra.get("database")
                or extra.get("bare")
                or ""
            )
            if svc:
                out["ORACLE_SERVICE"] = svc
    return out


def _parse_env_text(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines from markdown (fenced blocks preferred)."""
    chunks: list[str] = []
    fences = _FENCE.findall(text or "")
    if fences:
        chunks.extend(fences)
    else:
        chunks.append(text or "")

    out: dict[str, str] = {}
    for chunk in chunks:
        for line in chunk.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _ENV_LINE.match(stripped)
            if not match:
                continue
            key, value = match.group(1), match.group(2)
            if key not in _SECRET_ENV_KEYS:
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            out[key] = value
    return out


@dataclass(frozen=True, slots=True)
class InventorySshTarget:
    """One SSH-capable inventory row (host + auth).

    Attributes:
        host: IP address or hostname.
        port: SSH port (default ``22``).
        user: SSH username.
        password: SSH password when key auth is not used.
        private_key_path: Path to private key file.
        strict_host_key: ``true``/``false`` for host key checking.
        label: Original Access column label from the inventory table.
    """

    host: str
    port: str = "22"
    user: str = ""
    password: str = ""
    private_key_path: str = ""
    strict_host_key: str = ""
    label: str = ""

    @property
    def slug(self) -> str:
        """Filesystem-safe id derived from host (IP or hostname)."""
        raw = re.sub(r"[^A-Za-z0-9._-]+", "_", (self.host or "").strip()).strip("._-")
        return raw or "host"


def _iter_credential_rows(text: str) -> list[dict[str, str]]:
    """Yield raw credential table rows as dicts (access, host, port, …)."""
    lines = (text or "").splitlines()
    header_idx = -1
    headers: list[str] = []
    for i, line in enumerate(lines):
        match = _TABLE_ROW.match(line.strip())
        if not match:
            continue
        cells = [_cell(c) for c in match.group(1).split("|")]
        norms = [_norm_header(c) for c in cells]
        if any(h in {"access", "service", "type"} for h in norms) and any(
            h in {"host", "hosturl", "url", "endpoint"} for h in norms
        ):
            header_idx = i
            headers = norms
            break
    if header_idx < 0:
        return []

    def col(*aliases: str) -> int | None:
        """Return the first matching header column index, or None.

        Args:
            *aliases: Normalized header names to look up in order of preference.

        Returns:
            Zero-based column index, or ``None`` when none of the aliases exist.
        """
        for alias in aliases:
            if alias in headers:
                return headers.index(alias)
        return None

    i_access = col("access", "service", "type")
    i_host = col("hosturl", "host", "url", "endpoint", "address")
    i_port = col("port", "accessport", "tcpport")
    i_user = col("username", "user", "login")
    i_secret = col("passwordtoken", "password", "token", "secret", "passwd")
    i_extra = col("extra", "database", "notes", "path", "options")
    if i_access is None or i_host is None:
        return []

    rows: list[dict[str, str]] = []
    for line in lines[header_idx + 1 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if rows:
                break
            continue
        if re.match(r"^\|[\s|:-]+\|$", stripped):
            continue
        cells = [_cell(c) for c in stripped.strip("|").split("|")]
        if len(cells) < len(headers):
            cells.extend([""] * (len(headers) - len(cells)))
        access = cells[i_access] if i_access < len(cells) else ""
        host = cells[i_host] if i_host < len(cells) else ""
        port = cells[i_port] if i_port is not None and i_port < len(cells) else ""
        user = cells[i_user] if i_user is not None and i_user < len(cells) else ""
        secret = (
            cells[i_secret] if i_secret is not None and i_secret < len(cells) else ""
        )
        extra_raw = (
            cells[i_extra] if i_extra is not None and i_extra < len(cells) else ""
        )
        rows.append(
            {
                "access": access,
                "host": host,
                "port": port,
                "user": user,
                "secret": secret,
                "extra": extra_raw,
                "kind": _access_kind(access) or "",
            }
        )
    return rows


def list_inventory_ssh_targets(text: str) -> list[InventorySshTarget]:
    """Return every SSH-capable row from an inventory credentials table.

    Deduplicates by host (first row wins). Includes OS-labelled rows
    (e.g. ``1C Ubuntu``) when ``_access_kind`` maps them to ``ssh``.
    """
    seen: set[str] = set()
    out: list[InventorySshTarget] = []
    for row in _iter_credential_rows(text):
        if row.get("kind") != "ssh":
            continue
        host = (row.get("host") or "").strip()
        if not host or host.lower() in seen:
            continue
        seen.add(host.lower())
        extra = _parse_extra(row.get("extra") or "")
        out.append(
            InventorySshTarget(
                host=host,
                port=(row.get("port") or "22").strip() or "22",
                user=(row.get("user") or "").strip(),
                password=(row.get("secret") or "").strip(),
                private_key_path=extra.get("key") or "",
                strict_host_key=extra.get("strict_host_key") or "",
                label=(row.get("access") or "").strip(),
            )
        )
    return out


def list_client_ssh_targets(
    inventory_dir: Path | str,
    client_slug_name: str,
) -> list[InventorySshTarget]:
    """Load SSH targets from ``inventory/<client>/INVENTORY.md`` (+ connection.md)."""
    from auditor.host_facts import resolve_client_dir

    client_dir = resolve_client_dir(Path(inventory_dir), client_slug_name)
    targets: list[InventorySshTarget] = []
    seen: set[str] = set()
    for name in ("INVENTORY.md", "connection.md"):
        path = client_dir / name
        if not path.is_file():
            continue
        for target in list_inventory_ssh_targets(path.read_text(encoding="utf-8")):
            key = target.host.lower()
            if key in seen:
                continue
            seen.add(key)
            targets.append(target)
    return targets


def list_client_access_endpoints(
    inventory_dir: Path | str,
    client_slug_name: str,
) -> list[dict[str, str]]:
    """List inventory Access rows (SSH / PostgreSQL / …) for reachability tables.

    Args:
        inventory_dir: Root inventory directory.
        client_slug_name: Client folder slug.

    Returns:
        Rows with ``service``, ``host``, ``port``, ``kind`` (``ssh`` / ``pg`` / …).
        Deduplicated by ``kind|host|port``.
    """
    from auditor.host_facts import resolve_client_dir

    client_dir = resolve_client_dir(Path(inventory_dir), client_slug_name)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for name in ("INVENTORY.md", "connection.md"):
        path = client_dir / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for row in _iter_credential_rows(text):
            kind = (row.get("kind") or "").strip()
            host = (row.get("host") or "").strip()
            if kind not in {"ssh", "pg", "mysql", "oracle"} or not host:
                continue
            port = (row.get("port") or "").strip()
            if not port:
                port = {
                    "pg": "5432",
                    "mysql": "3306",
                    "oracle": "1521",
                    "ssh": "22",
                }.get(kind, "22")
            key = f"{kind}|{host.lower()}|{port}"
            if key in seen:
                continue
            seen.add(key)
            service = (row.get("access") or kind).strip() or kind
            out.append(
                {
                    "service": service,
                    "host": host,
                    "port": port,
                    "kind": kind,
                }
            )
    return out


_SSH_ENV_KEYS = (
    "SSH_HOST",
    "SSH_PORT",
    "SSH_USER",
    "SSH_PASSWORD",
    "SSH_PRIVATE_KEY_PATH",
    "SSH_STRICT_HOST_KEY",
)


@contextmanager
def bind_ssh_target(
    target: InventorySshTarget,
    *,
    environ: dict[str, str] | None = None,
) -> Iterator[None]:
    """Temporarily apply one SSH target for tool calls.

    **Default (``environ is None``):** bind via a run-scoped
    :class:`~auditor.runtime_target.RuntimeTarget` ContextVar so concurrent
    audits do not clobber process ``SSH_*`` / cached settings. SSH tools and
    :func:`~auditor.runtime_target.effective_settings` read the overlay.

    **Explicit ``environ=``:** mutate that dict (tests / offline helpers) and
    clear the settings cache — does not touch the ContextVar.

    Args:
        target: Inventory SSH row to bind.
        environ: Optional env dict to mutate. Omit for ContextVar binding.

    Yields:
        None — use as a context manager around tool calls for that host.
    """
    if environ is not None:
        from auditor.config import get_settings

        target_env = environ
        saved: dict[str, str | None] = {k: target_env.get(k) for k in _SSH_ENV_KEYS}
        try:
            target_env["SSH_HOST"] = target.host
            target_env["SSH_PORT"] = target.port or "22"
            if target.user:
                target_env["SSH_USER"] = target.user
            elif "SSH_USER" in target_env:
                del target_env["SSH_USER"]
            if target.password:
                target_env["SSH_PASSWORD"] = target.password
            elif "SSH_PASSWORD" in target_env:
                del target_env["SSH_PASSWORD"]
            if target.private_key_path:
                target_env["SSH_PRIVATE_KEY_PATH"] = target.private_key_path
            elif "SSH_PRIVATE_KEY_PATH" in target_env:
                del target_env["SSH_PRIVATE_KEY_PATH"]
            if target.strict_host_key:
                target_env["SSH_STRICT_HOST_KEY"] = target.strict_host_key
            get_settings.cache_clear()
            yield
        finally:
            for key, value in saved.items():
                if value is None:
                    target_env.pop(key, None)
                else:
                    target_env[key] = value
            get_settings.cache_clear()
        return

    from auditor.runtime_target import bind_runtime_target, runtime_target_from_ssh

    with bind_runtime_target(
        runtime_target_from_ssh(
            host=target.host,
            port=target.port or "22",
            user=target.user,
            password=target.password,
            private_key_path=target.private_key_path,
            strict_host_key=target.strict_host_key,
        )
    ):
        yield


def read_client_credentials(
    inventory_dir: Path | str,
    client_slug_name: str,
) -> dict[str, str]:
    """Parse SSH/PG keys from the client inventory without mutating env.

    Same file order as :func:`load_inventory_credentials` (``INVENTORY.md`` then
    ``connection.md``), but returns a new dict only — safe for concurrent runs.
    """
    from auditor.host_facts import resolve_client_dir

    client_dir = resolve_client_dir(Path(inventory_dir), client_slug_name)
    applied: dict[str, str] = {}
    for name in ("INVENTORY.md", "connection.md"):
        path = client_dir / name
        if not path.is_file():
            continue
        parsed = parse_inventory_credentials(path.read_text(encoding="utf-8"))
        for key, value in parsed.items():
            if key not in _SECRET_ENV_KEYS:
                continue
            applied[key] = value
    return applied


def parse_inventory_credentials(text: str) -> dict[str, str]:
    """Parse credentials from inventory markdown (table preferred, env fallback)."""
    table = _parse_credentials_table(text)
    env = _parse_env_text(text)
    # Table wins on overlapping keys; env fills gaps / legacy files.
    return {**env, **table}


def connection_secrets_path(secrets_dir: Path) -> Path | None:
    """Prefer ``connection.md``, else the only non-example ``*.md`` present."""
    preferred = secrets_dir / "connection.md"
    if preferred.is_file():
        return preferred
    candidates = sorted(
        p
        for p in secrets_dir.glob("*.md")
        if p.name.lower() not in {"readme.md"}
        and not p.name.endswith(".example.md")
    )
    return candidates[0] if len(candidates) == 1 else None


def load_connection_secrets(
    secrets_dir: Path | str | None = None,
    *,
    environ: dict[str, str] | None = None,
    override_existing: bool = False,
) -> dict[str, str]:
    """Load SSH/PG/MCP keys from ``secrets/connection.md`` into ``environ``.

    Existing process environment values win unless ``override_existing`` is true
    (so a one-off shell export still works for debugging).

    Returns:
        Mapping of keys applied (empty if no file / no keys).
    """
    root = Path(secrets_dir or os.environ.get("SECRETS_DIR") or "secrets")
    path = connection_secrets_path(root)
    if path is None:
        return {}

    parsed = _parse_env_text(path.read_text(encoding="utf-8"))
    if not parsed:
        return {}

    target = environ if environ is not None else os.environ
    applied: dict[str, str] = {}
    for key, value in parsed.items():
        if not override_existing and target.get(key):
            continue
        target[key] = value
        applied[key] = value
    return applied


def load_inventory_credentials(
    inventory_dir: Path | str,
    client_slug_name: str,
    *,
    environ: dict[str, str] | None = None,
    override_existing: bool = True,
) -> dict[str, str]:
    """Load SSH/PG keys from the client inventory folder.

    Reads, in order (later files override earlier for the same key when
    ``override_existing`` is true within this load):

    1. ``inventory/<client>/INVENTORY.md`` (credentials table, or legacy env)
    2. ``inventory/<client>/connection.md`` (optional dedicated secrets file)

    Client inventory credentials are meant to be the source of truth per
    engagement; pass ``override_existing=True`` (default) so they win over
    any process-wide ``secrets/connection.md`` defaults.
    """
    from auditor.host_facts import resolve_client_dir

    client_dir = resolve_client_dir(Path(inventory_dir), client_slug_name)
    target = environ if environ is not None else os.environ
    applied: dict[str, str] = {}

    for name in ("INVENTORY.md", "connection.md"):
        path = client_dir / name
        if not path.is_file():
            continue
        parsed = parse_inventory_credentials(path.read_text(encoding="utf-8"))
        for key, value in parsed.items():
            if key not in _SECRET_ENV_KEYS:
                continue
            if not override_existing and target.get(key):
                continue
            target[key] = value
            applied[key] = value
    return applied

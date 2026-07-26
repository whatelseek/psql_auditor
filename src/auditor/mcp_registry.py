"""Declarative MCP server registry (``mcps/registry.json``).

Operators add MCP servers by editing the registry — not by changing Python.
Credentials and target IPs are resolved from inventory / settings (``envFrom``)
at launch time and are never stored in the registry file.

Pipeline role:
    :mod:`auditor.tools.mcp_client` builds stdio connection dicts from this
    module. The assess agent can call ``mcp_list_servers`` to see what is
    enabled and whether credentials look ready.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from auditor.config import Settings

EnvFrom = Literal["inventory:pg", "inventory:mysql", "inventory:oracle", ""]


@dataclass(frozen=True, slots=True)
class McpServerSpec:
    """One MCP server entry from ``mcps/registry.json``.

    Attributes:
        name: Registry key (e.g. ``postgres``).
        enabled: When false, ignored by the runtime.
        transport: ``stdio`` or ``streamable_http`` (alias ``http``).
        command: Executable for stdio transport.
        args: CLI args for ``command``.
        url: Remote MCP endpoint for HTTP transports.
        env_from: Preset that fills connection env from inventory/settings.
        env_map: Optional ``MCP_ENV_VAR → process/settings key`` overlays.
        frameworks: Framework ids this MCP typically serves (empty = general).
        curated_tools: When true, use hand-written tool wrappers.
        blocked_tools: Remote tool names the client must not call.
        description: Short operator-facing blurb.
        extra_env: Static non-secret env from the registry (rarely needed).
    """

    name: str
    enabled: bool = True
    transport: str = "stdio"
    command: str = "npx"
    args: tuple[str, ...] = ()
    url: str = ""
    env_from: str = ""
    env_map: dict[str, str] = field(default_factory=dict)
    frameworks: tuple[str, ...] = ()
    curated_tools: bool = False
    blocked_tools: tuple[str, ...] = ()
    description: str = ""
    extra_env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class McpRegistry:
    """Parsed ``mcps/registry.json``."""

    version: int
    servers: dict[str, McpServerSpec]
    path: Path | None = None

    def enabled_servers(self) -> list[McpServerSpec]:
        """Return enabled specs in stable name order."""
        return [self.servers[k] for k in sorted(self.servers) if self.servers[k].enabled]

    def get(self, name: str) -> McpServerSpec | None:
        """Return a server by name, or ``None``."""
        return self.servers.get(name)


_ENV_PASSTHROUGH = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_CACHE_HOME",
        "npm_config_cache",
        "NPM_CONFIG_CACHE",
    }
)


def default_mcps_dir() -> Path:
    """Default ``mcps/`` directory (cwd-relative)."""
    return Path("mcps")


def load_mcp_registry(
    mcps_dir: Path | str | None = None,
    *,
    filename: str = "registry.json",
) -> McpRegistry:
    """Load and validate ``mcps/registry.json``.

    Args:
        mcps_dir: Directory containing the registry file.
        filename: Registry filename (default ``registry.json``).

    Returns:
        Parsed :class:`McpRegistry`. Missing file → empty registry (version 0).
    """
    root = Path(mcps_dir) if mcps_dir is not None else default_mcps_dir()
    path = root / filename
    if not path.is_file():
        return McpRegistry(version=0, servers={}, path=path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"MCP registry must be a JSON object: {path}")

    version = int(raw.get("version") or 1)
    servers_raw = raw.get("mcpServers") or raw.get("servers") or {}
    if not isinstance(servers_raw, dict):
        raise ValueError(f"mcpServers must be an object: {path}")

    servers: dict[str, McpServerSpec] = {}
    for name, entry in servers_raw.items():
        if not isinstance(entry, dict):
            continue
        args = entry.get("args") or []
        if not isinstance(args, list):
            raise ValueError(f"mcpServers.{name}.args must be a list")
        env_map = entry.get("envMap") or {}
        if not isinstance(env_map, dict):
            raise ValueError(f"mcpServers.{name}.envMap must be an object")
        frameworks = entry.get("frameworks") or []
        blocked = entry.get("blockedTools") or entry.get("blocked_tools") or []
        extra_env = entry.get("env") or {}
        if not isinstance(extra_env, dict):
            raise ValueError(f"mcpServers.{name}.env must be an object")
        # Reject obvious secret keys committed into the registry.
        for key in extra_env:
            low = str(key).lower()
            if any(tok in low for tok in ("password", "secret", "token", "api_key")):
                raise ValueError(
                    f"mcpServers.{name}.env must not contain secret key {key!r}; "
                    "use envFrom / inventory instead"
                )
        transport = str(entry.get("transport") or entry.get("type") or "stdio")
        transport = transport.strip().lower()
        if transport in {"http", "streamablehttp", "streamable-http"}:
            transport = "streamable_http"
        servers[str(name)] = McpServerSpec(
            name=str(name),
            enabled=bool(entry.get("enabled", True)),
            transport=transport,
            command=str(entry.get("command") or "npx"),
            args=tuple(str(a) for a in args),
            url=str(entry.get("url") or entry.get("serverUrl") or "").strip(),
            env_from=str(entry.get("envFrom") or entry.get("env_from") or "").strip(),
            env_map={str(k): str(v) for k, v in env_map.items()},
            frameworks=tuple(str(x) for x in frameworks),
            curated_tools=bool(entry.get("curatedTools", entry.get("curated_tools", False))),
            blocked_tools=tuple(str(x) for x in blocked),
            description=str(entry.get("description") or ""),
            extra_env={str(k): str(v) for k, v in extra_env.items() if v is not None},
        )
    return McpRegistry(version=version, servers=servers, path=path)


def _credential_env_from_os(prefix: str, *, port_default: str) -> dict[str, str]:
    """Collect ``PREFIX_HOST`` / ``_PORT`` / ``_USER`` / ``_PASSWORD`` / … from env."""
    mapping = {
        f"{prefix}_HOST": os.environ.get(f"{prefix}_HOST") or "",
        f"{prefix}_PORT": os.environ.get(f"{prefix}_PORT") or port_default,
        f"{prefix}_USER": os.environ.get(f"{prefix}_USER") or "",
        f"{prefix}_PASSWORD": os.environ.get(f"{prefix}_PASSWORD") or "",
    }
    if prefix == "MYSQL":
        mapping["MYSQL_DATABASE"] = os.environ.get("MYSQL_DATABASE") or ""
    elif prefix == "ORACLE":
        mapping["ORACLE_SERVICE"] = (
            os.environ.get("ORACLE_SERVICE") or os.environ.get("ORACLE_DATABASE") or ""
        )
    return {k: v for k, v in mapping.items() if v}


def resolve_env_from(
    env_from: str,
    settings: Settings,
) -> dict[str, str]:
    """Resolve an ``envFrom`` preset into MCP child-process env vars.

    Args:
        env_from: e.g. ``inventory:pg``, ``inventory:mysql``, ``inventory:oracle``.
        settings: Application settings (Postgres fields for ``inventory:pg``).

    Returns:
        Env overlay (may be empty when credentials are missing).
    """
    key = (env_from or "").strip().lower()
    if key in {"inventory:pg", "pg", "postgres"}:
        return dict(settings.pg_env_for_mcp())
    if key in {"inventory:mysql", "mysql", "mariadb"}:
        return _credential_env_from_os("MYSQL", port_default="3306")
    if key in {"inventory:oracle", "oracle"}:
        return _credential_env_from_os("ORACLE", port_default="1521")
    return {}


def resolve_env_map(
    env_map: dict[str, str],
    *,
    settings: Settings | None = None,
) -> dict[str, str]:
    """Map registry ``envMap`` (MCP_VAR → source key) using settings/os.environ.

    For Postgres, source keys ``PG_*`` also resolve via ``settings.pg_env_for_mcp``.
    """
    del settings  # reserved for future typed lookups
    out: dict[str, str] = {}
    for dest, source in (env_map or {}).items():
        src = str(source).strip()
        if not src:
            continue
        val = os.environ.get(src) or ""
        if val:
            out[str(dest)] = val
    return out


def base_passthrough_env() -> dict[str, str]:
    """Minimal parent env safe to pass into an MCP subprocess."""
    env: dict[str, str] = {
        k: v
        for k, v in os.environ.items()
        if isinstance(v, str)
        and (k in _ENV_PASSTHROUGH or k.startswith("NODE") or k.startswith("NPM"))
    }
    return env


def credentials_ready(spec: McpServerSpec, settings: Settings) -> bool:
    """Heuristic: enough host + secret-like fields to launch usefully.

    Remote HTTP docs servers with no ``envFrom`` are always ready (no auth).
    """
    if not (spec.env_from or "").strip() and not spec.env_map:
        # Public / no-credential MCP (e.g. Microsoft Learn).
        if spec.transport in {"streamable_http", "sse", "websocket"}:
            return bool(spec.url)
        if not spec.extra_env:
            return True
    env = resolve_server_env(spec, settings)
    host_keys = [k for k in env if k.endswith("_HOST") or k == "PG_HOST"]
    secret_keys = [
        k for k in env if any(tok in k.upper() for tok in ("PASSWORD", "TOKEN", "SECRET"))
    ]
    has_host = any(env.get(k) for k in host_keys) or bool(env.get("DATABASE_URL"))
    has_secret = any(env.get(k) for k in secret_keys) or bool(env.get("DATABASE_URL"))
    if spec.env_from.endswith("pg") or "pg" in spec.env_from:
        fields = settings.resolve_pg_fields()
        has_host = has_host or bool(fields.get("host"))
        has_secret = has_secret or bool(fields.get("password"))
    return bool(has_host and has_secret)


def resolve_server_env(spec: McpServerSpec, settings: Settings) -> dict[str, str]:
    """Build the full env overlay for one MCP server (no passthrough yet)."""
    env: dict[str, str] = {}
    env.update(resolve_env_from(spec.env_from, settings))
    env.update(resolve_env_map(spec.env_map, settings=settings))
    env.update(spec.extra_env)
    return env


def build_stdio_connection(
    spec: McpServerSpec,
    settings: Settings,
    *,
    command_override: str | None = None,
    args_override: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Build a ``MultiServerMCPClient`` stdio connection dict for ``spec``.

    Args:
        spec: Registry server entry.
        settings: Used for ``envFrom`` resolution.
        command_override: Optional command (e.g. legacy ``MCP_POSTGRES_COMMAND``).
        args_override: Optional args list override.

    Returns:
        Dict with ``transport``, ``command``, ``args``, ``env``.

    Raises:
        ValueError: Unsupported transport.
    """
    if spec.transport != "stdio":
        raise ValueError(
            f"MCP server {spec.name!r}: transport {spec.transport!r} "
            "is not stdio (use build_http_connection)"
        )
    command = (command_override or spec.command or "npx").strip()
    if args_override is not None:
        args = [str(a) for a in args_override]
    else:
        args = list(spec.args)
    env = base_passthrough_env()
    env.update(resolve_server_env(spec, settings))
    return {
        "transport": "stdio",
        "command": command,
        "args": args,
        "env": env,
    }


def build_http_connection(
    spec: McpServerSpec,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Build a ``MultiServerMCPClient`` streamable HTTP connection dict.

    Args:
        spec: Registry server with ``transport=streamable_http`` and ``url``.
        settings: Unused today; reserved for future auth headers from inventory.

    Returns:
        Dict with ``transport`` and ``url``.

    Raises:
        ValueError: Wrong transport or missing URL.
    """
    del settings
    if spec.transport not in {"streamable_http", "sse"}:
        raise ValueError(
            f"MCP server {spec.name!r}: transport {spec.transport!r} is not an HTTP transport"
        )
    url = (spec.url or "").strip()
    if not url:
        raise ValueError(f"MCP server {spec.name!r}: url is required for HTTP transport")
    transport = "streamable_http" if spec.transport == "streamable_http" else "sse"
    return {"transport": transport, "url": url}


def format_registry_markdown(
    registry: McpRegistry,
    settings: Settings,
) -> str:
    """Operator/agent-facing table of registered MCP servers."""
    lines = [
        "### MCP registry",
        "",
        f"_Source: `{registry.path or 'mcps/registry.json'}`_",
        "",
        "| Server | Enabled | Credentials | Frameworks | Curated | Description |",
        "|--------|---------|-------------|------------|---------|-------------|",
    ]
    if not registry.servers:
        lines.append("| — | — | — | — | — | _(empty registry)_ |")
        lines.append("")
        return "\n".join(lines)

    for name in sorted(registry.servers):
        spec = registry.servers[name]
        if not (spec.env_from or "").strip() and not spec.env_map:
            ready = "n/a" if credentials_ready(spec, settings) else "missing"
        else:
            ready = "yes" if credentials_ready(spec, settings) else "missing"
        fws = ", ".join(f"`{x}`" for x in spec.frameworks) or "any"
        curated = "yes" if spec.curated_tools else "no"
        enabled = "yes" if spec.enabled else "no"
        desc = (spec.description or "—").replace("|", "/")
        if spec.url:
            desc = f"{desc} ({spec.url})"
        lines.append(f"| `{name}` | {enabled} | {ready} | {fws} | {curated} | {desc} |")
    lines.append("")
    lines.append(
        "Credentials and IPs come from **inventory / secrets** "
        "(`envFrom`) when required — not from `registry.json`. "
        "Public HTTP MCPs (e.g. Microsoft Learn) need no inventory secrets."
    )
    lines.append("")
    return "\n".join(lines)

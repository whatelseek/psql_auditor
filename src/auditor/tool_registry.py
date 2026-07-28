"""Administrator-managed tool registry and capability policy (INPUT-004).

Discovers versioned tool manifests under ``tools/catalog/``, validates them,
and exposes only authorized, executable tools for LLM binding. Invalid tools
remain visible in the catalog but are never bound.

Each audit plan/run pins ``tool_catalog_hash`` and ``capability_policy_hash``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal, NoReturn

from auditor.domain.audit_request import POC_TOOL_PROFILE

ValidationLevel = Literal["error", "warning", "information"]

_SECRET_ENV_TOKENS = ("password", "secret", "token", "api_key", "private_key")


@dataclass(frozen=True, slots=True)
class ToolValidationIssue:
    """One validation finding for a tool manifest or policy."""

    level: ValidationLevel
    code: str
    message: str
    tool_id: str = ""
    location: str = ""


@dataclass(frozen=True, slots=True)
class ToolManifest:
    """Validated (or invalid) versioned tool manifest."""

    id: str
    version: str
    title: str
    description: str
    transport: str
    adapter: str
    capabilities: tuple[str, ...]
    risk: str
    readonly: bool
    inventory_access: tuple[str, ...]
    credential_source: str
    blocked_operations: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int
    enabled: bool
    profiles: tuple[str, ...]
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    source_path: str = ""
    source_hash: str = ""
    issues: tuple[ToolValidationIssue, ...] = ()

    @property
    def executable(self) -> bool:
        return self.enabled and not any(i.level == "error" for i in self.issues)


@dataclass(frozen=True, slots=True)
class CapabilityPolicy:
    """Immutable capability-policy snapshot for a tool profile."""

    version: str
    profile: str
    description: str
    readonly_required: bool
    allowed_tools: tuple[str, ...]
    denied_tools: tuple[str, ...]
    allowed_transports: tuple[str, ...]
    max_output_chars: int
    require_inventory_credentials: bool
    source_path: str = ""
    source_hash: str = ""
    issues: tuple[ToolValidationIssue, ...] = ()

    @property
    def executable(self) -> bool:
        return not any(i.level == "error" for i in self.issues)


@dataclass(frozen=True, slots=True)
class ToolCatalogEntry:
    """Compact catalog row for operators / preflight prompts."""

    id: str
    version: str
    title: str
    transport: str
    readonly: bool
    executable: bool
    profiles: tuple[str, ...]
    validation_errors: tuple[str, ...] = ()


@dataclass(slots=True)
class ToolRegistry:
    """Loaded tool catalog + active capability policy."""

    tools: dict[str, ToolManifest] = field(default_factory=dict)
    policy: CapabilityPolicy | None = None
    catalog_dir: Path | None = None
    policy_path: Path | None = None
    catalog_hash: str = ""
    policy_hash: str = ""

    def list_tools(self, *, executable_only: bool = False) -> list[ToolManifest]:
        items = [self.tools[k] for k in sorted(self.tools)]
        if executable_only:
            return [t for t in items if t.executable]
        return items

    def get(self, tool_id: str) -> ToolManifest | None:
        return self.tools.get((tool_id or "").strip())

    def catalog(self, *, executable_only: bool = False) -> list[ToolCatalogEntry]:
        rows: list[ToolCatalogEntry] = []
        for tool in self.list_tools(executable_only=False):
            if executable_only and not self.is_authorized(tool.id):
                continue
            errors = tuple(i.message for i in tool.issues if i.level == "error")
            rows.append(
                ToolCatalogEntry(
                    id=tool.id,
                    version=tool.version,
                    title=tool.title,
                    transport=tool.transport,
                    readonly=tool.readonly,
                    executable=self.is_authorized(tool.id),
                    profiles=tool.profiles,
                    validation_errors=errors,
                )
            )
        return rows

    def is_authorized(self, tool_id: str) -> bool:
        """Return True when the tool is executable and allowed by the policy."""
        tool = self.get(tool_id)
        if tool is None or not tool.executable:
            return False
        policy = self.policy
        if policy is None or not policy.executable:
            return False
        if tool_id in policy.denied_tools:
            return False
        if policy.allowed_tools and tool_id not in policy.allowed_tools:
            return False
        if policy.allowed_transports and tool.transport not in policy.allowed_transports:
            return False
        if policy.readonly_required and not tool.readonly:
            return False
        if tool.profiles and policy.profile not in tool.profiles:
            return False
        return True

    def authorized_tools(
        self,
        *,
        transports: Iterable[str] | None = None,
    ) -> list[ToolManifest]:
        wanted = {t.lower() for t in transports} if transports is not None else None
        out: list[ToolManifest] = []
        for tool in self.list_tools():
            if not self.is_authorized(tool.id):
                continue
            if wanted is not None and tool.transport.lower() not in wanted:
                continue
            out.append(tool)
        return out

    def bindable_langchain_tools(
        self,
        *,
        transports: Iterable[str] | None = None,
    ) -> list[Any]:
        """Return LangChain tools for authorized manifests only."""
        tools: list[Any] = []
        for manifest in self.authorized_tools(transports=transports):
            bound = _resolve_langchain_tool(manifest)
            if bound is not None:
                tools.append(bound)
        return tools

    def require_authorized(self, tool_id: str) -> ToolManifest:
        tool = self.get(tool_id)
        if tool is None:
            raise ToolNotAuthorized(f"unknown tool {tool_id!r}", code="unknown_tool")
        if not tool.executable:
            msgs = "; ".join(i.message for i in tool.issues if i.level == "error")
            raise ToolNotAuthorized(
                f"tool {tool_id!r} is not executable: {msgs or 'validation errors'}",
                code="tool_not_executable",
            )
        if not self.is_authorized(tool_id):
            raise ToolNotAuthorized(
                f"tool {tool_id!r} is not authorized by capability policy",
                code="tool_unauthorized",
            )
        return tool

    def snapshot_hashes(self) -> dict[str, str]:
        return {
            "tool_catalog_hash": self.catalog_hash,
            "capability_policy_hash": self.policy_hash,
        }


class ToolNotAuthorized(ValueError):
    """Raised when a tool cannot be bound or invoked under the active policy."""

    def __init__(self, message: str, *, code: str = "tool_unauthorized") -> None:
        self.code = code
        super().__init__(message)


class RuntimeToolCatalogError(RuntimeError):
    """Raised when the runtime tool catalog/policy fails startup validation."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        tool_id: str = "",
        catalog_path: str = "",
        policy_profile: str = "",
    ) -> None:
        self.code = code
        self.tool_id = tool_id
        self.catalog_path = catalog_path
        self.policy_profile = policy_profile
        super().__init__(message)


# POC profile requires these SSH tools to be authorized and LangChain-bindable.
REQUIRED_POC_SSH_TOOL_IDS: tuple[str, ...] = ("ssh_run", "ssh_read_file")


def default_tools_dir() -> Path:
    """Default ``tools/`` directory (cwd-relative)."""
    return Path("tools")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _short_hash(digest: str) -> str:
    return f"tool-{digest[:12]}"


def _policy_short_hash(digest: str) -> str:
    return f"pol-{digest[:12]}"


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"tool manifest must be a JSON object: {path}")
    return raw


def _parse_positive_int(
    raw: Any,
    *,
    default: int,
    field_name: str,
    tool_id: str,
    path: Path,
    issues: list[ToolValidationIssue],
) -> int:
    """Parse a positive int field; malformed values become validation issues."""
    if raw is None or raw == "":
        return default
    try:
        if isinstance(raw, bool):
            raise TypeError("bool is not a valid integer field")
        value = int(raw)
    except (TypeError, ValueError):
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_numeric_field",
                message=f"{field_name} must be a positive integer (got {raw!r})",
                tool_id=tool_id,
                location=str(path),
            )
        )
        return default
    if value <= 0:
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_numeric_field",
                message=f"{field_name} must be > 0 (got {value})",
                tool_id=tool_id,
                location=str(path),
            )
        )
        return default
    return value


def _parse_bool(
    raw: Any,
    *,
    default: bool,
    field_name: str,
    tool_id: str,
    path: Path,
    issues: list[ToolValidationIssue],
) -> bool:
    """Parse a boolean field; malformed values become validation issues."""
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)) and raw in (0, 1) and not isinstance(raw, bool):
        # Reject bare integers other than explicit JSON true/false.
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_boolean_field",
                message=f"{field_name} must be a boolean (got {raw!r})",
                tool_id=tool_id,
                location=str(path),
            )
        )
        return default
    if isinstance(raw, str):
        low = raw.strip().lower()
        if low in {"true", "yes", "1"}:
            return True
        if low in {"false", "no", "0"}:
            return False
    issues.append(
        ToolValidationIssue(
            level="error",
            code="invalid_boolean_field",
            message=f"{field_name} must be a boolean (got {raw!r})",
            tool_id=tool_id,
            location=str(path),
        )
    )
    return default


def _with_issue(manifest: ToolManifest, issue: ToolValidationIssue) -> ToolManifest:
    """Return a copy of ``manifest`` with an added issue (and enabled cleared on error)."""
    issues = tuple(manifest.issues) + (issue,)
    enabled = manifest.enabled and not any(i.level == "error" for i in issues)
    return ToolManifest(
        id=manifest.id,
        version=manifest.version,
        title=manifest.title,
        description=manifest.description,
        transport=manifest.transport,
        adapter=manifest.adapter,
        capabilities=manifest.capabilities,
        risk=manifest.risk,
        readonly=manifest.readonly,
        inventory_access=manifest.inventory_access,
        credential_source=manifest.credential_source,
        blocked_operations=manifest.blocked_operations,
        timeout_seconds=manifest.timeout_seconds,
        max_output_bytes=manifest.max_output_bytes,
        enabled=enabled,
        profiles=manifest.profiles,
        input_schema=manifest.input_schema,
        output_schema=manifest.output_schema,
        source_path=manifest.source_path,
        source_hash=manifest.source_hash,
        issues=issues,
    )


def _validate_manifest(raw: dict[str, Any], *, path: Path, source_hash: str) -> ToolManifest:
    issues: list[ToolValidationIssue] = []
    tool_id = str(raw.get("id") or "").strip()
    if not tool_id:
        issues.append(
            ToolValidationIssue(
                level="error",
                code="missing_id",
                message="manifest id is required",
                location=str(path),
            )
        )
        tool_id = path.stem

    version = str(raw.get("version") or "").strip()
    if not version:
        issues.append(
            ToolValidationIssue(
                level="error",
                code="missing_version",
                message="manifest version is required",
                tool_id=tool_id,
                location=str(path),
            )
        )

    adapter = str(raw.get("adapter") or "").strip()
    if not adapter or ":" not in adapter:
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_adapter",
                message="adapter must be 'module:attr'",
                tool_id=tool_id,
                location=str(path),
            )
        )

    transport = str(raw.get("transport") or "").strip().lower()
    if not transport:
        issues.append(
            ToolValidationIssue(
                level="error",
                code="missing_transport",
                message="transport is required",
                tool_id=tool_id,
                location=str(path),
            )
        )

    # Reject secret-shaped static config blocks if present.
    for key in ("env", "credentials", "secrets"):
        block = raw.get(key)
        if isinstance(block, dict):
            for env_key in block:
                low = str(env_key).lower()
                if any(tok in low for tok in _SECRET_ENV_TOKENS):
                    issues.append(
                        ToolValidationIssue(
                            level="error",
                            code="secret_in_manifest",
                            message=(
                                f"manifest must not contain secret key {env_key!r}; "
                                "resolve credentials from inventory/run context"
                            ),
                            tool_id=tool_id,
                            location=str(path),
                        )
                    )

    input_schema = raw.get("input_schema") or raw.get("inputSchema") or {}
    output_schema = raw.get("output_schema") or raw.get("outputSchema") or {}
    if not isinstance(input_schema, dict):
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_input_schema",
                message="input_schema must be an object",
                tool_id=tool_id,
                location=str(path),
            )
        )
        input_schema = {}
    if not isinstance(output_schema, dict):
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_output_schema",
                message="output_schema must be an object",
                tool_id=tool_id,
                location=str(path),
            )
        )
        output_schema = {}

    caps = raw.get("capabilities") or []
    if not isinstance(caps, list) or not caps:
        issues.append(
            ToolValidationIssue(
                level="error",
                code="missing_capabilities",
                message="capabilities must be a non-empty list",
                tool_id=tool_id,
                location=str(path),
            )
        )
        caps = []

    profiles = raw.get("profiles") or [POC_TOOL_PROFILE]
    if not isinstance(profiles, list):
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_profiles",
                message="profiles must be a list",
                tool_id=tool_id,
                location=str(path),
            )
        )
        profiles = []

    timeout = _parse_positive_int(
        raw.get("timeout_seconds"),
        default=30,
        field_name="timeout_seconds",
        tool_id=tool_id,
        path=path,
        issues=issues,
    )
    max_out = _parse_positive_int(
        raw.get("max_output_bytes"),
        default=200_000,
        field_name="max_output_bytes",
        tool_id=tool_id,
        path=path,
        issues=issues,
    )
    readonly = _parse_bool(
        raw.get("readonly", True),
        default=True,
        field_name="readonly",
        tool_id=tool_id,
        path=path,
        issues=issues,
    )
    enabled = _parse_bool(
        raw.get("enabled", True),
        default=True,
        field_name="enabled",
        tool_id=tool_id,
        path=path,
        issues=issues,
    )

    inventory_access = raw.get("inventory_access") or []
    blocked = raw.get("blocked_operations") or []
    if not isinstance(inventory_access, list):
        inventory_access = []
    if not isinstance(blocked, list):
        blocked = []

    return ToolManifest(
        id=tool_id,
        version=version or "0",
        title=str(raw.get("title") or tool_id),
        description=str(raw.get("description") or ""),
        transport=transport,
        adapter=adapter,
        capabilities=tuple(str(c) for c in caps),
        risk=str(raw.get("risk") or "low"),
        readonly=readonly,
        inventory_access=tuple(str(x) for x in inventory_access),
        credential_source=str(raw.get("credential_source") or ""),
        blocked_operations=tuple(str(x) for x in blocked),
        timeout_seconds=timeout,
        max_output_bytes=max_out,
        enabled=enabled,
        profiles=tuple(str(p) for p in profiles),
        input_schema=dict(input_schema),
        output_schema=dict(output_schema),
        source_path=str(path),
        source_hash=source_hash,
        issues=tuple(issues),
    )


def _validate_policy(raw: dict[str, Any], *, path: Path, source_hash: str) -> CapabilityPolicy:
    issues: list[ToolValidationIssue] = []
    profile = str(raw.get("profile") or "").strip()
    if not profile:
        issues.append(
            ToolValidationIssue(
                level="error",
                code="missing_profile",
                message="capability policy profile is required",
                location=str(path),
            )
        )
    version = str(raw.get("version") or "").strip() or "0"
    allowed = raw.get("allowed_tools") or []
    denied = raw.get("denied_tools") or []
    transports = raw.get("allowed_transports") or []
    if not isinstance(allowed, list):
        issues.append(
            ToolValidationIssue(
                level="error",
                code="invalid_allowed_tools",
                message="allowed_tools must be a list",
                location=str(path),
            )
        )
        allowed = []
    if not isinstance(denied, list):
        denied = []
    if not isinstance(transports, list):
        transports = []
    max_chars_issues: list[ToolValidationIssue] = []
    max_chars = _parse_positive_int(
        raw.get("max_output_chars"),
        default=6000,
        field_name="max_output_chars",
        tool_id="",
        path=path,
        issues=max_chars_issues,
    )
    issues.extend(max_chars_issues)
    readonly_required = _parse_bool(
        raw.get("readonly_required", True),
        default=True,
        field_name="readonly_required",
        tool_id="",
        path=path,
        issues=issues,
    )
    require_inventory_credentials = _parse_bool(
        raw.get("require_inventory_credentials", True),
        default=True,
        field_name="require_inventory_credentials",
        tool_id="",
        path=path,
        issues=issues,
    )
    return CapabilityPolicy(
        version=version,
        profile=profile or POC_TOOL_PROFILE,
        description=str(raw.get("description") or ""),
        readonly_required=readonly_required,
        allowed_tools=tuple(str(x) for x in allowed),
        denied_tools=tuple(str(x) for x in denied),
        allowed_transports=tuple(str(x).lower() for x in transports),
        max_output_chars=max_chars,
        require_inventory_credentials=require_inventory_credentials,
        source_path=str(path),
        source_hash=source_hash,
        issues=tuple(issues),
    )


def _resolve_langchain_tool(manifest: ToolManifest) -> Any | None:
    """Import the module:attr adapter and return a LangChain tool if present."""
    module_name, _, attr = manifest.adapter.partition(":")
    if not module_name or not attr:
        return None
    try:
        module = importlib.import_module(module_name)
    except Exception:  # noqa: BLE001
        return None
    target = getattr(module, attr, None)
    if target is None:
        return None
    # Prefer a sibling LangChain tool named after the manifest id when the
    # adapter is an invoke helper (e.g. invoke_ssh_run → ssh_run).
    if callable(target) and getattr(target, "name", None) == manifest.id:
        return target
    langchain_name = manifest.id
    sibling = getattr(module, langchain_name, None)
    if sibling is not None and getattr(sibling, "name", None) == langchain_name:
        return sibling
    # Adapter may itself be a LangChain StructuredTool.
    if getattr(target, "name", None):
        return target
    return None


def load_capability_policy(
    tools_dir: Path | str | None = None,
    *,
    profile: str = POC_TOOL_PROFILE,
) -> CapabilityPolicy:
    """Load ``tools/policies/<profile>.json``."""
    root = Path(tools_dir) if tools_dir is not None else default_tools_dir()
    path = root / "policies" / f"{profile}.json"
    if not path.is_file():
        return CapabilityPolicy(
            version="0",
            profile=profile,
            description="",
            readonly_required=True,
            allowed_tools=(),
            denied_tools=(),
            allowed_transports=(),
            max_output_chars=6000,
            require_inventory_credentials=True,
            source_path=str(path),
            source_hash="",
            issues=(
                ToolValidationIssue(
                    level="error",
                    code="policy_missing",
                    message=f"capability policy not found: {path}",
                    location=str(path),
                ),
            ),
        )
    text = path.read_text(encoding="utf-8")
    digest = _sha256_text(text)
    raw = json.loads(text)
    if not isinstance(raw, dict):
        raise ValueError(f"capability policy must be a JSON object: {path}")
    return _validate_policy(raw, path=path, source_hash=digest)


def load_tool_registry(
    tools_dir: Path | str | None = None,
    *,
    profile: str = POC_TOOL_PROFILE,
) -> ToolRegistry:
    """Load and validate tool manifests + the active capability policy.

    Invalid manifests remain in the registry (visible) but ``executable`` is
    false so they are never authorized for binding.
    """
    root = Path(tools_dir) if tools_dir is not None else default_tools_dir()
    catalog_dir = root / "catalog"
    tools: dict[str, ToolManifest] = {}
    hash_parts: list[str] = []

    if catalog_dir.is_dir():
        for path in sorted(catalog_dir.glob("*.json")):
            text = path.read_text(encoding="utf-8")
            digest = _sha256_text(text)
            hash_parts.append(f"{path.name}:{digest}")
            try:
                raw = _load_json(path)
            except Exception as exc:  # noqa: BLE001
                tool_id = path.stem
                tools[tool_id] = ToolManifest(
                    id=tool_id,
                    version="0",
                    title=tool_id,
                    description="",
                    transport="",
                    adapter="",
                    capabilities=(),
                    risk="unknown",
                    readonly=True,
                    inventory_access=(),
                    credential_source="",
                    blocked_operations=(),
                    timeout_seconds=30,
                    max_output_bytes=200_000,
                    enabled=False,
                    profiles=(),
                    input_schema={},
                    output_schema={},
                    source_path=str(path),
                    source_hash=digest,
                    issues=(
                        ToolValidationIssue(
                            level="error",
                            code="invalid_json",
                            message=f"failed to parse manifest: {exc}",
                            tool_id=tool_id,
                            location=str(path),
                        ),
                    ),
                )
                continue
            manifest = _validate_manifest(raw, path=path, source_hash=digest)
            # Duplicate ids: every conflicting manifest becomes non-executable.
            if manifest.id in tools:
                first = tools[manifest.id]
                tools[manifest.id] = _with_issue(
                    first,
                    ToolValidationIssue(
                        level="error",
                        code="duplicate_id",
                        message=(
                            f"duplicate tool id {manifest.id!r} (also defined in {path.name})"
                        ),
                        tool_id=manifest.id,
                        location=first.source_path or str(path),
                    ),
                )
                conflict = _with_issue(
                    manifest,
                    ToolValidationIssue(
                        level="error",
                        code="duplicate_id",
                        message=(
                            f"duplicate tool id {manifest.id!r} (also defined in "
                            f"{Path(first.source_path).name if first.source_path else 'catalog'})"
                        ),
                        tool_id=manifest.id,
                        location=str(path),
                    ),
                )
                tools[f"{manifest.id}#{path.stem}"] = conflict
                continue
            tools[manifest.id] = manifest

    # Second pass: if any id appears under multiple storage keys, ensure none
    # of those entries remain executable without a duplicate_id error.
    by_id: dict[str, list[str]] = {}
    for key, tool in tools.items():
        by_id.setdefault(tool.id, []).append(key)
    for tool_id, keys in by_id.items():
        if len(keys) < 2:
            continue
        for key in keys:
            tool = tools[key]
            if any(i.code == "duplicate_id" for i in tool.issues):
                continue
            tools[key] = _with_issue(
                tool,
                ToolValidationIssue(
                    level="error",
                    code="duplicate_id",
                    message=f"duplicate tool id {tool_id!r}",
                    tool_id=tool_id,
                    location=tool.source_path,
                ),
            )

    policy = load_capability_policy(root, profile=profile)
    catalog_digest = _sha256_text("\n".join(hash_parts) if hash_parts else "empty-catalog")
    return ToolRegistry(
        tools=tools,
        policy=policy,
        catalog_dir=catalog_dir,
        policy_path=Path(policy.source_path) if policy.source_path else None,
        catalog_hash=_short_hash(catalog_digest),
        policy_hash=_policy_short_hash(policy.source_hash or _sha256_text(policy.profile)),
    )


# Process-level cache keyed by normalized tools directory + profile.
_CACHED: dict[tuple[str, str], ToolRegistry] = {}


def _registry_cache_key(
    tools_dir: Path | str | None,
    profile: str,
) -> tuple[str, str]:
    root = Path(tools_dir) if tools_dir is not None else default_tools_dir()
    return (str(root.resolve()), profile)


def get_tool_registry(
    *,
    tools_dir: Path | str | None = None,
    profile: str = POC_TOOL_PROFILE,
    refresh: bool = False,
) -> ToolRegistry:
    """Return the tool registry, caching by normalized directory and profile."""
    key = _registry_cache_key(tools_dir, profile)
    if refresh or key not in _CACHED:
        _CACHED[key] = load_tool_registry(tools_dir, profile=profile)
    return _CACHED[key]


def reset_tool_registry_cache() -> None:
    """Drop all cached registries (tests)."""
    _CACHED.clear()


def validate_runtime_tool_registry(
    registry: ToolRegistry,
    *,
    required_tool_ids: tuple[str, ...] = REQUIRED_POC_SSH_TOOL_IDS,
    tools_dir: Path | str | None = None,
) -> None:
    """Fail closed when the active catalog/policy cannot support runtime tools.

    Raises:
        RuntimeToolCatalogError: missing paths, invalid policy, unauthorized or
            non-bindable required tools, or bound-name mismatches. Messages must
            never include credentials, tokens, inventory contents, or tool inputs.
    """
    if tools_dir is not None:
        root = Path(tools_dir)
    elif registry.catalog_dir is not None:
        root = Path(registry.catalog_dir).parent
    else:
        root = default_tools_dir()

    catalog_dir = root / "catalog"
    catalog_path = str(registry.catalog_dir or catalog_dir)
    policy = registry.policy
    profile = policy.profile if policy is not None else ""

    def _fail(
        message: str,
        *,
        code: str,
        tool_id: str = "",
    ) -> NoReturn:
        raise RuntimeToolCatalogError(
            message,
            code=code,
            tool_id=tool_id,
            catalog_path=catalog_path,
            policy_profile=profile,
        )

    if not root.is_dir():
        _fail(f"tools directory missing: {root}", code="tools_dir_missing")
    if not catalog_dir.is_dir():
        _fail(f"tool catalog directory missing: {catalog_dir}", code="catalog_dir_missing")

    if policy is None:
        _fail("capability policy is missing", code="policy_missing")

    if any(i.code == "policy_missing" for i in policy.issues):
        policy_file = root / "policies" / f"{policy.profile}.json"
        _fail(f"capability policy file missing: {policy_file}", code="policy_missing")

    policy_errors = [i for i in policy.issues if i.level == "error"]
    if policy_errors:
        issue = policy_errors[0]
        _fail(
            f"capability policy invalid ({issue.code}): {issue.message}",
            code=issue.code or "policy_invalid",
        )

    for allowed_id in policy.allowed_tools:
        if registry.get(allowed_id) is None:
            _fail(
                f"capability policy allows unknown tool {allowed_id!r}",
                code="unknown_allowed_tool",
                tool_id=allowed_id,
            )

    for tool_id in required_tool_ids:
        manifest = registry.get(tool_id)
        if manifest is None:
            _fail(
                f"required tool manifest missing: {tool_id!r}",
                code="required_tool_missing",
                tool_id=tool_id,
            )
        if not manifest.enabled:
            _fail(
                f"required tool is disabled: {tool_id!r}",
                code="required_tool_disabled",
                tool_id=tool_id,
            )
        if not manifest.executable:
            err = next(
                (i.message for i in manifest.issues if i.level == "error"),
                "validation errors",
            )
            _fail(
                f"required tool manifest invalid: {tool_id!r} ({err})",
                code="required_tool_invalid",
                tool_id=tool_id,
            )
        if tool_id in policy.denied_tools:
            _fail(
                f"required tool denied by capability policy: {tool_id!r}",
                code="required_tool_denied",
                tool_id=tool_id,
            )
        if policy.allowed_transports and manifest.transport not in policy.allowed_transports:
            _fail(
                f"required tool transport {manifest.transport!r} denied for {tool_id!r}",
                code="required_transport_denied",
                tool_id=tool_id,
            )
        if not registry.is_authorized(tool_id):
            _fail(
                f"required tool is not authorized: {tool_id!r}",
                code="required_tool_unauthorized",
                tool_id=tool_id,
            )

        bound = _resolve_langchain_tool(manifest)
        if bound is None:
            _fail(
                f"required tool cannot be bound as a LangChain tool: {tool_id!r}",
                code="required_tool_not_bindable",
                tool_id=tool_id,
            )
        bound_name = getattr(bound, "name", None)
        if bound_name != tool_id:
            _fail(
                f"bound tool name {bound_name!r} does not match manifest id {tool_id!r}",
                code="bound_name_mismatch",
                tool_id=tool_id,
            )


class ToolSnapshotStale(ValueError):
    """Raised when pinned tool/policy hashes diverge from the live registry."""

    def __init__(self, message: str, *, code: str = "tool_snapshot_stale") -> None:
        self.code = code
        super().__init__(message)


def assert_tool_snapshot_current(
    *,
    tool_catalog_hash: str = "",
    capability_policy_hash: str = "",
    tools_dir: Path | str | None = None,
    profile: str = POC_TOOL_PROFILE,
) -> dict[str, str]:
    """Reject confirm/start/invoke when pinned hashes differ from the live registry.

    Empty pins are ignored (legacy plans). When a pin is present it must match.
    """
    registry = get_tool_registry(tools_dir=tools_dir, profile=profile)
    current = registry.snapshot_hashes()
    pinned_catalog = (tool_catalog_hash or "").strip()
    pinned_policy = (capability_policy_hash or "").strip()
    if pinned_catalog and pinned_catalog != current["tool_catalog_hash"]:
        raise ToolSnapshotStale(
            "tool catalog hash mismatch: plan/run pin "
            f"{pinned_catalog!r} != current {current['tool_catalog_hash']!r}; "
            "re-run inventory analyze / audit plan",
            code="tool_snapshot_stale",
        )
    if pinned_policy and pinned_policy != current["capability_policy_hash"]:
        raise ToolSnapshotStale(
            "capability policy hash mismatch: plan/run pin "
            f"{pinned_policy!r} != current {current['capability_policy_hash']!r}; "
            "re-run inventory analyze / audit plan",
            code="tool_snapshot_stale",
        )
    return current

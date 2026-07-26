"""Strict, versioned ``AuditRequest`` input contract (INPUT-001).

Every new production audit creates jobs only from a validated, immutable,
secret-free request. Free-form operator text is non-authoritative narrative.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, NoReturn

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from auditor.client_registry import get_client_registry
from auditor.config import Settings
from auditor.frameworks import get_framework
from auditor.host_facts import resolve_client_dir, resolve_client_inventory
from auditor.legacy_compat import MissingClientIdError, require_client_id
from auditor.secrets_file import list_client_ssh_targets

AUDIT_REQUEST_SCHEMA_VERSION = 1
POC_TOOL_PROFILE = "poc_audit_v1"
SUPPORTED_TOOL_PROFILES: frozenset[str] = frozenset({POC_TOOL_PROFILE})

# Field names that must never appear on a request payload (secret canaries).
_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "password",
        "ssh_password",
        "winrm_password",
        "pg_password",
        "token",
        "api_key",
        "database_url",
        "private_key",
        "private_key_path",
        "ssh_private_key_path",
        "secret",
        "credentials",
    }
)


class AuditRequestIssue(BaseModel):
    """One machine-readable validation issue (never contains secrets)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    location: StrictStr
    code: StrictStr
    message: StrictStr


class AuditRequestRejected(ValueError):
    """Typed rejection of an invalid or unauthorized AuditRequest."""

    def __init__(
        self,
        *,
        issues: list[AuditRequestIssue] | list[dict[str, str]],
        code: str = "invalid_audit_request",
    ) -> None:
        parsed: list[AuditRequestIssue] = []
        for item in issues:
            if isinstance(item, AuditRequestIssue):
                parsed.append(item)
            else:
                parsed.append(AuditRequestIssue.model_validate(item))
        self.code = code
        self.issues = parsed
        detail = "; ".join(f"{i.location}: {i.message}" for i in parsed) or code
        super().__init__(detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "issues": [i.model_dump() for i in self.issues],
        }

    def operator_message(self) -> str:
        """Safe, operator-readable summary (no secrets)."""
        lines = ["Audit request rejected:", ""]
        for issue in self.issues:
            lines.append(f"- `{issue.location}` ({issue.code}): {issue.message}")
        return "\n".join(lines)


class InventoryReference(BaseModel):
    """Client-owned inventory file reference (INPUT-001 v1)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["client_file"]
    ref: StrictStr = Field(min_length=1)
    # Optional expected inventory snapshot identity (inventory-driven launch).
    version_id: StrictStr = ""
    content_hash: StrictStr = ""

    @field_validator("ref")
    @classmethod
    def _ref_relative(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("inventory.ref must be non-empty")
        path = Path(text)
        if path.is_absolute() or text.startswith(("/", "\\")):
            raise ValueError("inventory.ref must be relative to inventory_dir")
        if ".." in path.parts:
            raise ValueError("inventory.ref must not contain path traversal")
        return text.replace("\\", "/")

    @field_validator("version_id", "content_hash")
    @classmethod
    def _optional_identity(cls, value: str) -> str:
        return (value or "").strip()


class FrameworkReference(BaseModel):
    """Exact framework identity required by the request."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    framework_id: StrictStr = Field(min_length=1)
    framework_version: StrictStr = Field(min_length=1)

    @field_validator("framework_id", "framework_version")
    @classmethod
    def _strip_nonempty(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must be non-empty")
        return text


class AuditTarget(BaseModel):
    """One inventory target with one or more frameworks."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    inventory_target_ref: StrictStr = Field(min_length=1)
    frameworks: list[FrameworkReference] = Field(min_length=1)

    @field_validator("inventory_target_ref")
    @classmethod
    def _target_ref(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("inventory_target_ref must be non-empty")
        return text

    @model_validator(mode="after")
    def _unique_frameworks(self) -> AuditTarget:
        seen: set[tuple[str, str]] = set()
        for fw in self.frameworks:
            key = (fw.framework_id.lower(), fw.framework_version)
            if key in seen:
                raise ValueError(
                    f"duplicate framework pair {fw.framework_id!r}/{fw.framework_version!r}"
                )
            seen.add(key)
        return self


class AuditRunSettings(BaseModel):
    """Explicit run behavior snapshot (not inferred from free text)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    report_language: StrictStr = Field(min_length=2, max_length=8)
    hitl_enabled: StrictBool
    archive_enabled: StrictBool
    max_parallel_assessments: StrictInt
    max_parallel_host_jobs: StrictInt

    @field_validator("report_language")
    @classmethod
    def _lang(cls, value: str) -> str:
        text = value.strip().lower()
        if text not in {"en", "ru"}:
            raise ValueError("report_language must be 'en' or 'ru'")
        return text

    @field_validator("max_parallel_assessments")
    @classmethod
    def _assess(cls, value: int) -> int:
        if value < 1 or value > 32:
            raise ValueError("max_parallel_assessments out of range [1, 32]")
        return value

    @field_validator("max_parallel_host_jobs")
    @classmethod
    def _hosts(cls, value: int) -> int:
        if value < 1 or value > 4:
            raise ValueError("max_parallel_host_jobs out of range [1, 4]")
        return value


class AuditRequest(BaseModel):
    """Immutable versioned audit input contract."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal[1]
    client_id: StrictStr = Field(min_length=1)
    inventory: InventoryReference
    targets: list[AuditTarget] = Field(min_length=1)
    tool_profile: StrictStr = Field(min_length=1)
    run_settings: AuditRunSettings

    @field_validator("client_id")
    @classmethod
    def _client(cls, value: str) -> str:
        return require_client_id(value, context="AuditRequest.client_id")

    @field_validator("tool_profile")
    @classmethod
    def _profile(cls, value: str) -> str:
        text = value.strip()
        if text not in SUPPORTED_TOOL_PROFILES:
            raise ValueError(f"unknown tool_profile {text!r}")
        return text

    @model_validator(mode="before")
    @classmethod
    def _reject_secret_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            bad = sorted(k for k in data if str(k).lower() in _FORBIDDEN_SECRET_KEYS)
            if bad:
                raise ValueError(f"secret fields are forbidden on AuditRequest: {', '.join(bad)}")
        return data

    @model_validator(mode="after")
    def _unique_targets(self) -> AuditRequest:
        seen_refs: set[str] = set()
        seen_pairs: set[tuple[str, str, str]] = set()
        for target in self.targets:
            key = target.inventory_target_ref.lower()
            if key in seen_refs:
                raise ValueError(f"duplicate inventory_target_ref {target.inventory_target_ref!r}")
            seen_refs.add(key)
            for fw in target.frameworks:
                pair = (key, fw.framework_id.lower(), fw.framework_version)
                if pair in seen_pairs:
                    raise ValueError("duplicate target/framework pair")
                seen_pairs.add(pair)
        return self


def parse_audit_request(payload: Any) -> AuditRequest:
    """Parse and structurally validate a version-1 AuditRequest."""
    try:
        if isinstance(payload, AuditRequest):
            return payload
        return AuditRequest.model_validate(payload)
    except (ValidationError, MissingClientIdError, ValueError) as exc:
        issues = _issues_from_exc(exc)
        raise AuditRequestRejected(issues=issues) from exc


def _issues_from_exc(exc: BaseException) -> list[AuditRequestIssue]:
    if isinstance(exc, ValidationError):
        out: list[AuditRequestIssue] = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc") or ()) or "request"
            msg = str(err.get("msg") or "invalid")
            # Never echo input values that might contain secrets.
            out.append(
                AuditRequestIssue(
                    location=loc,
                    code=str(err.get("type") or "validation_error"),
                    message=msg,
                )
            )
        return out or [
            AuditRequestIssue(
                location="request",
                code="validation_error",
                message="invalid audit request",
            )
        ]
    return [
        AuditRequestIssue(
            location="request",
            code="validation_error",
            message=str(exc) or "invalid audit request",
        )
    ]


def _reject(location: str, code: str, message: str) -> NoReturn:
    raise AuditRequestRejected(
        issues=[AuditRequestIssue(location=location, code=code, message=message)]
    )


def _load_normalized_client_inventory(inventory_dir: Path, client_slug: str) -> Any:
    """Load current inventory via loader/normalizer (lazy import avoids cycles)."""
    # Imported lazily: auditor.inventory.__init__ pulls service → audit_request.
    from auditor.inventory.loaders import InventoryLoadError, load_raw_inventory
    from auditor.inventory.normalize import normalize_inventory

    root = Path(inventory_dir)
    # Prefer on-disk directory casing so normalized identity matches analyze/plan
    # (registry slugs are lowercased and would otherwise alter content_hash).
    client_dir = resolve_client_dir(root, client_slug)
    client_name = client_dir.name if client_dir.is_dir() else client_slug
    try:
        raw, source_path, source_format = load_raw_inventory(root, client_name)
    except InventoryLoadError as exc:
        _reject(
            "inventory.ref",
            "missing_inventory",
            f"client inventory could not be loaded: {exc}",
        )
    return normalize_inventory(
        raw,
        client_name=client_name,
        source_path=source_path,
        source_format=source_format,
    )


def validate_audit_request_semantics(
    request: AuditRequest,
    settings: Settings,
    *,
    evidence_dir: Path | None = None,
) -> AuditRequest:
    """Apply ownership, inventory, framework, and profile semantic checks."""
    evidence_root = Path(evidence_dir or settings.evidence_dir)
    try:
        client_id = require_client_id(request.client_id, context="validate_audit_request")
    except MissingClientIdError as exc:
        _reject("client_id", "invalid_client_id", str(exc))

    client = get_client_registry(evidence_root).get(client_id)
    if client is None:
        _reject("client_id", "unknown_client", f"unknown client_id {client_id!r}")

    inventory_dir = Path(settings.inventory_dir)
    ref_path = Path(request.inventory.ref)
    try:
        inventory_root = inventory_dir.resolve()
        resolved = (inventory_dir / ref_path).resolve()
    except OSError as exc:
        _reject("inventory.ref", "inventory_path_error", f"cannot resolve inventory path: {exc}")

    try:
        resolved.relative_to(inventory_root)
    except ValueError:
        _reject(
            "inventory.ref",
            "inventory_escape",
            "inventory.ref escapes Settings.inventory_dir",
        )

    # Symlink escape: resolved parent must stay under inventory_root.
    if resolved.is_symlink() or any(p.is_symlink() for p in resolved.parents):
        # Still require final resolve under inventory_root (already checked).
        pass

    client_dir = resolve_client_dir(inventory_dir, client.slug).resolve()
    try:
        resolved.relative_to(client_dir)
    except ValueError:
        _reject(
            "inventory.ref",
            "cross_client_inventory",
            "inventory.ref is not under the registered client's inventory directory",
        )

    inv_path, content, found = resolve_client_inventory(inventory_dir, client.slug)
    if (
        not found
        or inv_path is None
        or not inv_path.is_file()
        or not str(content or "").strip()
    ):
        _reject(
            "inventory.ref",
            "missing_inventory",
            "client inventory file is missing or empty",
        )
    if inv_path.resolve() != resolved:
        # Allow ref that points at the same file via normalized relative path.
        if resolved.name.lower() != "inventory.md" or resolved.parent != client_dir:
            _reject(
                "inventory.ref",
                "inventory_mismatch",
                "inventory.ref does not match the client INVENTORY.md path",
            )

    # Inventory-driven requests must pin normalized ClientInventory.version
    # identity so saved / replayed AuditRequest payloads fail closed after
    # inventory changes (compare normalized identity, not raw file bytes).
    expected_version = (request.inventory.version_id or "").strip()
    expected_hash = (request.inventory.content_hash or "").strip()
    missing_identity: list[AuditRequestIssue] = []
    if not expected_version:
        missing_identity.append(
            AuditRequestIssue(
                location="inventory.version_id",
                code="missing_inventory_version",
                message="inventory.version_id is required for inventory-driven requests",
            )
        )
    if not expected_hash:
        missing_identity.append(
            AuditRequestIssue(
                location="inventory.content_hash",
                code="missing_inventory_hash",
                message="inventory.content_hash is required for inventory-driven requests",
            )
        )
    if missing_identity:
        raise AuditRequestRejected(issues=missing_identity)

    current_inventory = _load_normalized_client_inventory(inventory_dir, client.slug)
    current_version = current_inventory.version.version_id
    current_hash = current_inventory.version.content_hash
    if expected_hash != current_hash:
        _reject(
            "inventory.content_hash",
            "inventory_hash_mismatch",
            "request inventory content_hash does not match the current normalized inventory",
        )
    if expected_version != current_version:
        _reject(
            "inventory.version_id",
            "inventory_version_mismatch",
            "request inventory version_id does not match the current normalized inventory",
        )

    targets = list_client_ssh_targets(inventory_dir, client.slug)
    by_ref = _index_inventory_targets(targets)
    if not targets:
        _reject("targets", "empty_inventory", "inventory has no SSH/WinRM targets")

    for idx, target in enumerate(request.targets):
        if target.inventory_target_ref.lower() not in by_ref:
            _reject(
                f"targets[{idx}].inventory_target_ref",
                "unresolved_target",
                f"inventory target {target.inventory_target_ref!r} was not found",
            )
        if not target.frameworks:
            _reject(
                f"targets[{idx}].frameworks",
                "empty_framework_scope",
                "At least one framework is required",
            )
        for jdx, fw_ref in enumerate(target.frameworks):
            fw = get_framework(fw_ref.framework_id, settings.agents_dir)
            if fw is None:
                _reject(
                    f"targets[{idx}].frameworks[{jdx}].framework_id",
                    "unknown_framework",
                    f"unknown framework_id {fw_ref.framework_id!r}",
                )
            current = str(getattr(fw, "version", "") or "").strip()
            if current != fw_ref.framework_version:
                _reject(
                    f"targets[{idx}].frameworks[{jdx}].framework_version",
                    "framework_version_mismatch",
                    f"framework {fw_ref.framework_id!r} current version is {current!r}",
                )

    if request.tool_profile not in SUPPORTED_TOOL_PROFILES:
        _reject("tool_profile", "unknown_tool_profile", "unknown tool profile")

    # Bound run settings against deployed runtime ceilings.
    if request.run_settings.max_parallel_assessments > int(settings.max_parallel_assessments):
        _reject(
            "run_settings.max_parallel_assessments",
            "out_of_range",
            "exceeds runtime max_parallel_assessments",
        )
    if request.run_settings.max_parallel_host_jobs > int(settings.max_parallel_host_jobs):
        _reject(
            "run_settings.max_parallel_host_jobs",
            "out_of_range",
            "exceeds runtime max_parallel_host_jobs",
        )
    return request


def _index_inventory_targets(targets: list[Any]) -> dict[str, Any]:
    indexed: dict[str, Any] = {}
    for target in targets:
        keys = {
            str(getattr(target, "inventory_key", "") or "").strip().lower(),
            str(getattr(target, "slug", "") or "").strip().lower(),
            str(getattr(target, "host", "") or "").strip().lower(),
            str(getattr(target, "label", "") or "").strip().lower(),
        }
        for key in keys:
            if key:
                indexed[key] = target
    return indexed


def resolve_inventory_target(
    settings: Settings,
    *,
    client_slug: str,
    inventory_target_ref: str,
) -> Any | None:
    """Re-resolve a live inventory target (credentials) by reference."""
    targets = list_client_ssh_targets(settings.inventory_dir, client_slug)
    return _index_inventory_targets(targets).get(inventory_target_ref.strip().lower())


def run_settings_from_settings(
    settings: Settings, *, report_language: str = "en"
) -> AuditRunSettings:
    """Snapshot explicit run settings from the application Settings object."""
    return AuditRunSettings(
        report_language=report_language if report_language in {"en", "ru"} else "en",
        hitl_enabled=bool(settings.hitl_enabled),
        archive_enabled=bool(settings.archive_enabled),
        max_parallel_assessments=int(settings.max_parallel_assessments),
        max_parallel_host_jobs=int(settings.max_parallel_host_jobs),
    )


def build_audit_request_from_selected_jobs(
    *,
    client_id: str,
    client_slug: str,
    selected_jobs: list[dict[str, Any]],
    settings: Settings,
    report_language: str = "en",
) -> AuditRequest:
    """Build a version-1 request from confirmed intake ``selected_jobs``."""
    if not selected_jobs:
        _reject("targets", "empty_framework_scope", "confirmed selected_jobs is empty")

    targets: list[dict[str, Any]] = []
    for row in selected_jobs:
        ref = str(row.get("host_id") or row.get("ssh_host") or row.get("hostname") or "").strip()
        if not ref:
            _reject("targets", "unresolved_target", "selected job is missing a target reference")
        fws_raw = [str(x) for x in (row.get("frameworks") or [])]
        frameworks: list[dict[str, str]] = []
        for fid in fws_raw:
            fw = get_framework(fid, settings.agents_dir)
            if fw is None:
                _reject("targets.frameworks", "unknown_framework", f"unknown framework_id {fid!r}")
            assert fw is not None
            frameworks.append(
                {
                    "framework_id": fw.id,
                    "framework_version": str(getattr(fw, "version", "") or ""),
                }
            )
        if not frameworks:
            _reject(
                "targets.frameworks",
                "empty_framework_scope",
                "At least one framework is required",
            )
        targets.append({"inventory_target_ref": ref, "frameworks": frameworks})

    current_inventory = _load_normalized_client_inventory(
        Path(settings.inventory_dir), client_slug
    )
    # Prefer on-disk directory casing for the inventory ref.
    source = Path(current_inventory.version.source_path)
    dir_name = source.parent.name if source.parent.name else client_slug

    payload = {
        "schema_version": AUDIT_REQUEST_SCHEMA_VERSION,
        "client_id": client_id,
        "inventory": {
            "kind": "client_file",
            "ref": f"{dir_name}/INVENTORY.md",
            "version_id": current_inventory.version.version_id,
            "content_hash": current_inventory.version.content_hash,
        },
        "targets": targets,
        "tool_profile": POC_TOOL_PROFILE,
        "run_settings": run_settings_from_settings(
            settings, report_language=report_language
        ).model_dump(),
    }
    request = parse_audit_request(payload)
    return validate_audit_request_semantics(request, settings)


def persistable_audit_request(request: AuditRequest) -> dict[str, Any]:
    """Secret-free dump suitable for AuditRun.scope / meta.json."""
    return request.model_dump(mode="json")


def load_persisted_audit_request(payload: Any) -> AuditRequest:
    """Load a previously persisted request snapshot (fail closed on bad versions)."""
    if not isinstance(payload, dict):
        _reject("audit_request", "missing_audit_request", "persisted audit_request is missing")
    version = payload.get("schema_version")
    if version != AUDIT_REQUEST_SCHEMA_VERSION:
        _reject(
            "schema_version",
            "unsupported_schema_version",
            f"unsupported input_contract_version {version!r}",
        )
    return parse_audit_request(payload)


def scope_with_audit_request(
    scope: dict[str, Any] | None,
    request: AuditRequest,
) -> dict[str, Any]:
    """Merge request snapshot into AuditRun.scope without credentials."""
    out = dict(scope or {})
    out["input_contract_version"] = AUDIT_REQUEST_SCHEMA_VERSION
    out["audit_request"] = persistable_audit_request(request)
    return out

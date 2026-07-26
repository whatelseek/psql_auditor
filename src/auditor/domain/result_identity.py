"""Canonical audit result identity (CORE-003).

Physical identity is ``result_id`` (UUID). Logical uniqueness is the full key
``(client_id, audit_run_id, asset_id, framework_id, framework_version,
requirement_id)``. ``requirement_id`` alone is never a result identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from uuid import uuid4


class IncompleteResultIdentityError(ValueError):
    """Raised when a result is missing mandatory identity fields."""


class DuplicateResultIdError(ValueError):
    """Raised when the same ``result_id`` is claimed by conflicting results."""


class DuplicateLogicalKeyError(ValueError):
    """Raised when two results share the same logical key with different ids."""

    def __init__(
        self,
        logical_key: ResultLogicalKey | Mapping[str, str],
        *,
        existing_result_id: str = "",
        new_result_id: str = "",
    ) -> None:
        if isinstance(logical_key, ResultLogicalKey):
            key = logical_key
        else:
            key = ResultLogicalKey.from_mapping(logical_key)
        self.logical_key = key
        self.existing_result_id = existing_result_id
        self.new_result_id = new_result_id
        parts = ", ".join(f"{k}={v!r}" for k, v in key.as_dict().items())
        super().__init__(
            "duplicate logical result key: "
            f"{parts}"
            + (
                f" (existing result_id={existing_result_id!r}, new result_id={new_result_id!r})"
                if existing_result_id or new_result_id
                else ""
            )
        )


@dataclass(frozen=True, slots=True)
class ResultLogicalKey:
    """Full logical uniqueness key for one persisted audit result."""

    client_id: str
    audit_run_id: str
    asset_id: str
    framework_id: str
    framework_version: str
    requirement_id: str

    def as_dict(self) -> dict[str, str]:
        return {
            "client_id": self.client_id,
            "audit_run_id": self.audit_run_id,
            "asset_id": self.asset_id,
            "framework_id": self.framework_id,
            "framework_version": self.framework_version,
            "requirement_id": self.requirement_id,
        }

    def as_tuple(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.client_id,
            self.audit_run_id,
            self.asset_id,
            self.framework_id,
            self.framework_version,
            self.requirement_id,
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ResultLogicalKey:
        return cls(
            client_id=str(data.get("client_id") or "").strip(),
            audit_run_id=str(data.get("audit_run_id") or "").strip(),
            asset_id=str(data.get("asset_id") or "").strip(),
            framework_id=str(data.get("framework_id") or "").strip(),
            framework_version=str(data.get("framework_version") or "").strip(),
            requirement_id=str(data.get("requirement_id") or data.get("req_id") or "").strip(),
        )


def new_result_id() -> str:
    """Return a new opaque result UUID string."""
    return str(uuid4())


def logical_key_of(finding: Any) -> ResultLogicalKey:
    """Extract the logical key from a Finding-like object or mapping."""
    if hasattr(finding, "model_dump"):
        data = finding.model_dump()
    elif isinstance(finding, Mapping):
        data = finding
    else:
        data = {
            "client_id": getattr(finding, "client_id", ""),
            "audit_run_id": getattr(finding, "audit_run_id", ""),
            "asset_id": getattr(finding, "asset_id", ""),
            "framework_id": getattr(finding, "framework_id", ""),
            "framework_version": getattr(finding, "framework_version", ""),
            "requirement_id": getattr(finding, "requirement_id", ""),
        }
    return ResultLogicalKey.from_mapping(data)


def result_id_of(finding: Any) -> str:
    if hasattr(finding, "result_id"):
        return str(getattr(finding, "result_id") or "").strip()
    if isinstance(finding, Mapping):
        return str(finding.get("result_id") or "").strip()
    return ""


def validate_result_identity(finding: Any, *, for_persist: bool = True) -> None:
    """Raise when identity fields are incomplete (mandatory for persistence)."""
    rid = result_id_of(finding)
    key = logical_key_of(finding)
    missing: list[str] = []
    if not rid:
        missing.append("result_id")
    for field_name, value in key.as_dict().items():
        if not value:
            missing.append(field_name)
    if missing:
        raise IncompleteResultIdentityError(
            "incomplete result identity; missing: " + ", ".join(missing)
        )
    if for_persist and not key.framework_version:
        raise IncompleteResultIdentityError(
            "framework_version is mandatory before a result can be persisted"
        )


def merge_result_maps(
    left: Mapping[str, Any] | None,
    right: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Merge two result maps keyed by ``result_id`` with conflict checks.

    - Same ``result_id`` + same logical key → right wins (correction/validation).
    - Same ``result_id`` + different logical key → :class:`DuplicateResultIdError`.
    - Different ``result_id`` + same logical key → :class:`DuplicateLogicalKeyError`.
    """
    out: dict[str, Any] = {}
    by_logical: dict[tuple[str, ...], str] = {}

    def _put(map_key: str, finding: Any) -> None:
        rid = result_id_of(finding)
        # Legacy checkpoints keyed findings by requirement_id — migrate once.
        if not rid and map_key.upper().startswith("REQ"):
            rid = new_result_id()
            if hasattr(finding, "result_id"):
                finding.result_id = rid
                if not getattr(finding, "requirement_id", None):
                    finding.requirement_id = map_key
            elif isinstance(finding, dict):
                finding = dict(finding)
                finding["result_id"] = rid
                finding.setdefault("requirement_id", map_key)
        if not rid:
            rid = (map_key or "").strip()
        if not rid:
            raise IncompleteResultIdentityError(
                "findings map entries must be keyed by result_id and carry result_id"
            )
        # Ensure the object carries result_id for later persistence.
        if hasattr(finding, "result_id") and not finding.result_id:
            finding.result_id = rid
        elif isinstance(finding, dict) and not finding.get("result_id"):
            finding = dict(finding)
            finding["result_id"] = rid
        key = logical_key_of(finding)
        key_t = key.as_tuple()
        complete = all(bool(part) for part in key_t)
        # Incomplete logical keys (legacy checkpoints / mid-construction) merge
        # by result_id only; persistence validates the full key separately.
        if rid in out:
            prev = out[rid]
            prev_key = logical_key_of(prev)
            prev_complete = all(bool(part) for part in prev_key.as_tuple())
            if complete and prev_complete and prev_key.as_tuple() != key_t:
                raise DuplicateResultIdError(
                    f"duplicate result_id {rid!r} with conflicting logical keys: "
                    f"{prev_key.as_dict()} vs {key.as_dict()}"
                )
            out[rid] = finding
            if complete:
                by_logical[key_t] = rid
            return
        if complete:
            existing_rid = by_logical.get(key_t)
            if existing_rid is not None and existing_rid != rid:
                raise DuplicateLogicalKeyError(
                    key,
                    existing_result_id=existing_rid,
                    new_result_id=rid,
                )
            by_logical[key_t] = rid
        out[rid] = finding

    for map_key, finding in (left or {}).items():
        _put(str(map_key), finding)
    for map_key, finding in (right or {}).items():
        _put(str(map_key), finding)
    return out


def index_by_result_id(findings: Iterable[Any]) -> dict[str, Any]:
    """Build a ``result_id → finding`` map; reject conflicts."""
    return merge_result_maps({}, {result_id_of(f): f for f in findings if result_id_of(f)})


def finding_for_requirement(findings: Mapping[str, Any] | None, requirement_id: str) -> Any | None:
    """Return the finding for ``requirement_id`` within a scoped map.

    This is a field lookup, not an identity index. Raises if more than one
    finding in the map shares the same ``requirement_id`` (caller scope too wide).
    """
    rid = (requirement_id or "").strip()
    if not rid:
        return None
    matches = [
        f
        for f in (findings or {}).values()
        if str(
            getattr(f, "requirement_id", None)
            or (f.get("requirement_id") if isinstance(f, Mapping) else "")
            or ""
        ).strip()
        == rid
    ]
    if len(matches) > 1:
        keys = [logical_key_of(f).as_dict() for f in matches]
        raise DuplicateLogicalKeyError(
            keys[0],
            existing_result_id=result_id_of(matches[0]),
            new_result_id=result_id_of(matches[1]),
        )
    return matches[0] if matches else None


def requirement_ids_in(findings: Mapping[str, Any] | None) -> set[str]:
    """Return requirement_id values present in a result_id-keyed map."""
    out: set[str] = set()
    for f in (findings or {}).values():
        rid = str(
            getattr(f, "requirement_id", None)
            or (f.get("requirement_id") if isinstance(f, Mapping) else "")
            or ""
        ).strip()
        if rid:
            out.add(rid)
    return out

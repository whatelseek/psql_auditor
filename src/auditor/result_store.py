"""In-process audit result store with CORE-003 conflict checks.

Used by tests and as the application-boundary validator before warehouse
writes. Does not silently overwrite conflicting identities.
"""

from __future__ import annotations

from typing import Any, Iterable

from auditor.domain.result_identity import (
    DuplicateLogicalKeyError,
    DuplicateResultIdError,
    ResultLogicalKey,
    logical_key_of,
    merge_result_maps,
    result_id_of,
    validate_result_identity,
)
from auditor.state import Finding


class ResultStore:
    """Persistable result index keyed by ``result_id``."""

    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}
        self._by_logical: dict[tuple[str, ...], str] = {}

    def __len__(self) -> int:
        return len(self._by_id)

    def all(self) -> list[Finding]:
        return list(self._by_id.values())

    def get(self, result_id: str) -> Finding | None:
        return self._by_id.get(result_id)

    def put(self, finding: Finding, *, allow_update: bool = True) -> Finding:
        """Insert or update one result; raise on identity conflicts."""
        validate_result_identity(finding, for_persist=True)
        rid = finding.result_id
        key = logical_key_of(finding).as_tuple()
        if rid in self._by_id:
            prev = self._by_id[rid]
            if logical_key_of(prev).as_tuple() != key:
                raise DuplicateResultIdError(
                    f"duplicate result_id {rid!r} with conflicting logical keys: "
                    f"{logical_key_of(prev).as_dict()} vs {logical_key_of(finding).as_dict()}"
                )
            if not allow_update:
                raise DuplicateResultIdError(f"duplicate result_id {rid!r}")
            self._by_id[rid] = finding
            self._by_logical[key] = rid
            return finding
        existing = self._by_logical.get(key)
        if existing is not None and existing != rid:
            raise DuplicateLogicalKeyError(
                ResultLogicalKey(
                    client_id=finding.client_id,
                    audit_run_id=finding.audit_run_id,
                    asset_id=finding.asset_id,
                    framework_id=finding.framework_id,
                    framework_version=finding.framework_version,
                    requirement_id=finding.requirement_id,
                ),
                existing_result_id=existing,
                new_result_id=rid,
            )
        self._by_id[rid] = finding
        self._by_logical[key] = rid
        return finding

    def put_many(self, findings: Iterable[Finding]) -> list[Finding]:
        return [self.put(f) for f in findings]

    def as_map(self) -> dict[str, Finding]:
        return dict(self._by_id)

    def merge_maps(self, *maps: dict[str, Finding] | None) -> dict[str, Finding]:
        """Merge maps through conflict checks and replace store contents."""
        merged: dict[str, Any] = {}
        for m in maps:
            merged = merge_result_maps(merged, m)
        self._by_id = {
            rid: (f if isinstance(f, Finding) else Finding.model_validate(f))
            for rid, f in merged.items()
        }
        self._by_logical = {
            logical_key_of(f).as_tuple(): result_id_of(f) for f in self._by_id.values()
        }
        return self.as_map()

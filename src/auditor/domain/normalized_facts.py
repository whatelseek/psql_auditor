"""Normalized host fact namespace with provenance (INPUT005-11).

Builds deterministic, secret-free facts from structured inventory fields and
technology detections. Conflicts are never silently last-write-wins.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Mapping, Sequence

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictStr,
    field_validator,
    model_validator,
)

from auditor.domain.applicability import (
    FactValue,
    coerce_fact_value,
    validate_fact_key,
)
from auditor.domain.inventory import (
    ClientInventory,
    InventoryHost,
    TechnologyDetection,
)

FactSourceType = Literal[
    "inventory",
    "discovery",
    "operator",
    "derived",
]

_SOURCE_TIEBREAK: dict[FactSourceType, int] = {
    "operator": 0,
    "discovery": 1,
    "inventory": 2,
    "derived": 3,
}

_SAFE_SEGMENT_RE = re.compile(r"[^a-z0-9_-]+")


def _safe_segment(raw: str) -> str:
    text = str(raw or "").strip().lower().replace(" ", "_")
    text = _SAFE_SEGMENT_RE.sub("", text)
    text = text.strip("_-")
    return text


def _dedupe_sorted(refs: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({str(r).strip() for r in refs if str(r).strip()}))


class NormalizedFact(BaseModel):
    """One provenance-bearing fact in the normalized host namespace."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fact: StrictStr = Field(min_length=1)
    value: FactValue
    confidence: StrictFloat
    source_type: FactSourceType
    source_ref: StrictStr = Field(min_length=1)
    evidence_refs: tuple[StrictStr, ...] = ()

    @field_validator("fact")
    @classmethod
    def _fact_key(cls, value: str) -> str:
        return validate_fact_key(value)

    @field_validator("value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Any:
        return coerce_fact_value(value)

    @field_validator("confidence")
    @classmethod
    def _confidence(cls, value: float) -> float:
        if value < 0.0 or value > 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        return value

    @field_validator("source_ref")
    @classmethod
    def _source_ref(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("source_ref must be non-empty")
        return text

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, list):
            return _dedupe_sorted(value)
        if isinstance(value, tuple):
            return _dedupe_sorted(value)
        return value

    @model_validator(mode="after")
    def _sorted_evidence(self) -> NormalizedFact:
        refs = _dedupe_sorted(self.evidence_refs)
        if refs != self.evidence_refs:
            return self.model_copy(update={"evidence_refs": refs})
        return self


class FactConflict(BaseModel):
    """Same fact key observed with incompatible values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fact: StrictStr = Field(min_length=1)
    candidates: tuple[NormalizedFact, ...]
    reason: StrictStr = Field(min_length=1)

    @field_validator("fact")
    @classmethod
    def _fact_key(cls, value: str) -> str:
        return validate_fact_key(value)

    @field_validator("candidates")
    @classmethod
    def _candidates(cls, value: tuple[NormalizedFact, ...]) -> tuple[NormalizedFact, ...]:
        if len(value) < 2:
            raise ValueError("FactConflict requires at least two candidates")
        return tuple(
            sorted(
                value,
                key=lambda f: (
                    _SOURCE_TIEBREAK.get(f.source_type, 99),
                    f.source_ref,
                    repr(f.value),
                    f.confidence,
                ),
            )
        )


class HostFactSet(BaseModel):
    """Normalized facts for one inventory host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host_id: StrictStr = Field(min_length=1)
    facts: tuple[NormalizedFact, ...] = ()
    conflicts: tuple[FactConflict, ...] = ()

    def as_value_map(self) -> dict[str, FactValue]:
        """Return non-conflicted facts as a sorted key → value map."""
        conflicted = {c.fact for c in self.conflicts}
        items = {f.fact: f.value for f in self.facts if f.fact not in conflicted}
        return {key: items[key] for key in sorted(items)}

    def fact_by_key(self, key: str) -> NormalizedFact | None:
        """Return the active fact for ``key``, or ``None`` if missing/conflicted."""
        if any(c.fact == key for c in self.conflicts):
            return None
        for fact in self.facts:
            if fact.fact == key:
                return fact
        return None


def _values_equal(left: FactValue, right: FactValue) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return left.strip().lower() == right.strip().lower()
    return left == right


def _merge_same_value(facts: Sequence[NormalizedFact]) -> NormalizedFact:
    ordered = sorted(
        facts,
        key=lambda f: (
            _SOURCE_TIEBREAK.get(f.source_type, 99),
            f.source_ref,
            -f.confidence,
        ),
    )
    primary = ordered[0]
    evidence = _dedupe_sorted([ref for f in facts for ref in f.evidence_refs])
    confidence = max(f.confidence for f in facts)
    return primary.model_copy(
        update={
            "confidence": confidence,
            "evidence_refs": evidence,
        }
    )


def _reconcile_facts(host_id: str, facts: Sequence[NormalizedFact]) -> HostFactSet:
    by_key: dict[str, list[NormalizedFact]] = {}
    for fact in facts:
        by_key.setdefault(fact.fact, []).append(fact)

    active: list[NormalizedFact] = []
    conflicts: list[FactConflict] = []
    for key in sorted(by_key):
        group = by_key[key]
        if len(group) == 1:
            active.append(group[0])
            continue
        # Partition by equal values
        buckets: list[list[NormalizedFact]] = []
        for fact in group:
            placed = False
            for bucket in buckets:
                if _values_equal(bucket[0].value, fact.value):
                    bucket.append(fact)
                    placed = True
                    break
            if not placed:
                buckets.append([fact])
        if len(buckets) == 1:
            active.append(_merge_same_value(buckets[0]))
            continue
        # Different values → conflict; remove from active facts
        candidates = tuple(item for bucket in buckets for item in bucket)
        conflicts.append(
            FactConflict(
                fact=key,
                candidates=candidates,
                reason=f"conflicting values for {key} on host {host_id}",
            )
        )

    active_sorted = tuple(sorted(active, key=lambda f: f.fact))
    conflicts_sorted = tuple(sorted(conflicts, key=lambda c: c.fact))
    return HostFactSet(host_id=host_id, facts=active_sorted, conflicts=conflicts_sorted)


def _inventory_source_ref(inventory_version_id: str, host_id: str) -> str:
    return f"inventory:{inventory_version_id}#host:{host_id}"


def _detection_source_ref(target_id: str, technology_id: str) -> str:
    return f"detection:{target_id}#technology:{technology_id}"


def _parent_host_id(target_id: str) -> str:
    text = str(target_id or "").strip()
    if not text:
        return ""
    if "/" in text:
        return text.split("/", 1)[0].strip()
    return text


def build_host_fact_set(
    host: InventoryHost,
    *,
    inventory_version_id: str,
    detections: Sequence[TechnologyDetection] = (),
    extra_facts: Sequence[NormalizedFact] = (),
) -> HostFactSet:
    """Build a normalized fact set from structured inventory + detections."""
    version_id = str(inventory_version_id or "").strip()
    if not version_id:
        raise ValueError("inventory_version_id must be non-empty")

    source_ref = _inventory_source_ref(version_id, host.host_id)
    collected: list[NormalizedFact] = []

    def _add(
        key: str,
        value: FactValue,
        *,
        confidence: float = 1.0,
        source_type: FactSourceType = "inventory",
        src: str | None = None,
        evidence: Sequence[str] = (),
    ) -> None:
        collected.append(
            NormalizedFact(
                fact=key,
                value=value,
                confidence=confidence,
                source_type=source_type,
                source_ref=src or source_ref,
                evidence_refs=tuple(evidence),
            )
        )

    _add("asset.id", host.host_id)
    if host.asset_type.strip():
        _add("asset.type", host.asset_type.strip().lower())
    if host.vendor.strip():
        _add("asset.vendor", host.vendor.strip())
    if host.roles:
        roles = tuple(sorted({r.strip().lower() for r in host.roles if r.strip()}))
        if roles:
            _add("asset.roles", roles)
    if host.os_family.strip():
        _add("os.family", host.os_family.strip().lower())
    if host.os_name.strip():
        _add("os.name", host.os_name.strip())

    connections = {c.strip().lower() for c in host.connection_types if c.strip()}
    _add("access.ssh.available", "ssh" in connections)
    _add("access.winrm.available", "winrm" in connections)
    _add("access.postgresql.available", "postgresql" in connections)

    for service in host.services:
        seg = _safe_segment(service.name)
        if not seg:
            continue
        _add(
            f"service.{seg}.status",
            str(service.status),
            confidence=float(service.confidence),
        )
        if service.port is not None:
            _add(
                f"port.{int(service.port)}.status",
                "open",
                confidence=float(service.confidence),
            )

    for det in detections:
        parent = _parent_host_id(det.target_id)
        if parent != host.host_id:
            continue
        tech = _safe_segment(det.technology_id)
        if not tech:
            continue
        _add(
            f"technology.{tech}.status",
            str(det.status),
            confidence=float(det.confidence),
            source_type="discovery" if det.source == "discovered" else "inventory",
            src=_detection_source_ref(det.target_id, det.technology_id),
            evidence=det.evidence,
        )

    for extra in extra_facts:
        collected.append(extra)

    return _reconcile_facts(host.host_id, collected)


def build_inventory_fact_sets(
    inventory: ClientInventory,
    detections: Sequence[TechnologyDetection],
    *,
    extras: Mapping[str, Sequence[NormalizedFact]] | None = None,
) -> dict[str, HostFactSet]:
    """Build one fact set per inventory host with stable ordering."""
    extras = extras or {}
    host_ids = {h.host_id for h in inventory.hosts}
    # Ignore detections whose parent host is unknown — do not attach elsewhere.
    by_host: dict[str, list[TechnologyDetection]] = {h.host_id: [] for h in inventory.hosts}
    for det in detections:
        parent = _parent_host_id(det.target_id)
        if parent in host_ids:
            by_host[parent].append(det)

    result: dict[str, HostFactSet] = {}
    for host in sorted(inventory.hosts, key=lambda h: h.host_id):
        result[host.host_id] = build_host_fact_set(
            host,
            inventory_version_id=inventory.version.version_id,
            detections=by_host.get(host.host_id, ()),
            extra_facts=extras.get(host.host_id, ()),
        )
    return result


def facts_to_serializable(
    fact_sets: Mapping[str, HostFactSet],
) -> dict[str, object]:
    """Deterministic JSON-serializable dump of host fact sets (secret-free)."""
    payload: dict[str, object] = {}
    for host_id in sorted(fact_sets):
        fact_set = fact_sets[host_id]
        payload[host_id] = {
            "host_id": fact_set.host_id,
            "facts": [
                {
                    "fact": f.fact,
                    "value": list(f.value) if isinstance(f.value, tuple) else f.value,
                    "confidence": f.confidence,
                    "source_type": f.source_type,
                    "source_ref": f.source_ref,
                    "evidence_refs": list(f.evidence_refs),
                }
                for f in sorted(fact_set.facts, key=lambda x: x.fact)
            ],
            "conflicts": [
                {
                    "fact": c.fact,
                    "reason": c.reason,
                    "candidates": [
                        {
                            "fact": f.fact,
                            "value": list(f.value) if isinstance(f.value, tuple) else f.value,
                            "confidence": f.confidence,
                            "source_type": f.source_type,
                            "source_ref": f.source_ref,
                            "evidence_refs": list(f.evidence_refs),
                        }
                        for f in c.candidates
                    ],
                }
                for c in sorted(fact_set.conflicts, key=lambda x: x.fact)
            ],
        }
    return payload

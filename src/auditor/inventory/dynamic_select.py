"""Declarative production framework selection (INPUT005-13).

Selects frameworks from typed Markdown applicability metadata and normalized
facts. Does not use hardcoded technology→framework maps.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from auditor.domain.inventory import (
    ClientInventory,
    FrameworkSelectionDecision,
    TechnologyDetection,
)
from auditor.domain.normalized_facts import HostFactSet, build_inventory_fact_sets
from auditor.frameworks import _normalize_framework_language
from auditor.inventory.framework_candidates import (
    FrameworkCandidate,
    evaluate_framework_candidates,
)
from auditor.tool_registry import ToolRegistry

_WEAK_STATUS_VALUES = frozenset({"suspected", "possible", "probable", "unknown"})

_FAMILY_INCONSISTENT_REASON = "Framework family variants have inconsistent applicability metadata"
_INVALID_REASON = "Framework is not executable or applicability metadata is invalid"
_LEGACY_REASON = "Framework has no structured applicability metadata"
_NOT_MATCHED_REASON = "Declarative applicability did not match normalized facts"
_MISSING_EVIDENCE_REASON = "Required normalized facts are missing or conflicted"
_CAPABILITY_BLOCKED_REASON = "Required authorized capability is unavailable for the target"
_WEAK_STATUS_REASON = "Applicability matched only weak or unknown status evidence"
_MATCHED_REASON = "Declarative applicability matched normalized facts"
_HOST_VALIDATION_REASON = "Host has inventory validation errors"
_NO_ELIGIBLE_HOSTS_REASON = "No eligible hosts remain after inventory validation"


@dataclass(frozen=True, slots=True)
class _CatalogVariant:
    family_id: str
    framework_id: str
    framework_version: str
    language: str
    metadata_state: str
    fingerprint: str
    target_scope: str | None
    target_service: str


@dataclass(frozen=True, slots=True)
class _ResolvedVariant:
    target_id: str
    family_id: str
    framework_id: str
    framework_version: str
    language: str
    metadata_state: str
    fingerprint: str
    status: str
    reason: str
    missing_capabilities: tuple[str, ...]
    structured_valid: bool


def _normalize_status_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    return normalized or None


def _resolve_target_id(candidate: FrameworkCandidate, *, client_id: str) -> str:
    if candidate.target_scope == "client":
        return f"client:{client_id}"
    if candidate.target_scope == "service":
        return f"{candidate.host_id}/{candidate.target_service}"
    return candidate.host_id


def _aggregate_client_predicate(results: Sequence[str | None]) -> str:
    """Fail-closed aggregation across hosts for a client-scoped variant."""
    normalized = [r if r is not None else "invalid" for r in results]
    if any(r == "invalid" for r in normalized):
        return "invalid"
    if any(r == "not_matched" for r in normalized):
        return "not_matched"
    if any(r == "missing_evidence" for r in normalized):
        return "missing_evidence"
    if all(r == "matched" for r in normalized):
        return "matched"
    return "invalid"


def _union_sorted(*groups: Sequence[str]) -> tuple[str, ...]:
    merged: set[str] = set()
    for group in groups:
        merged.update(group)
    return tuple(sorted(merged))


def _weak_status_only(
    matched_fact_keys: Sequence[str],
    value_maps: Sequence[Mapping[str, object]],
) -> bool:
    status_keys = [k for k in matched_fact_keys if k.endswith(".status")]
    if not status_keys:
        return False
    values: list[str] = []
    for value_map in value_maps:
        for key in status_keys:
            if key not in value_map:
                continue
            normalized = _normalize_status_value(value_map[key])
            if normalized is not None:
                values.append(normalized)
    if not values:
        return False
    if any(v == "confirmed" for v in values):
        return False
    return any(v in _WEAK_STATUS_VALUES for v in values)


def _decision_fields(
    *,
    metadata_state: str,
    predicate_result: str | None,
    capability_ready: bool,
    missing_capabilities: tuple[str, ...],
    matched_fact_keys: tuple[str, ...],
    value_maps: Sequence[Mapping[str, object]],
    host_blocked: bool = False,
) -> tuple[str, str, tuple[str, ...]]:
    """Return ``(status, reason, missing_capabilities)``."""
    if metadata_state == "invalid" or predicate_result == "invalid":
        return "blocked", _INVALID_REASON, ()
    if host_blocked and predicate_result == "not_matched":
        return "not_applicable", _NOT_MATCHED_REASON, ()
    if host_blocked and metadata_state == "legacy":
        return "blocked", _HOST_VALIDATION_REASON, ()
    if host_blocked and predicate_result in {"matched", "missing_evidence"}:
        return "blocked", _HOST_VALIDATION_REASON, ()
    if host_blocked and predicate_result is None:
        return "blocked", _HOST_VALIDATION_REASON, ()
    if metadata_state == "legacy" or predicate_result is None:
        return "requires_operator_decision", _LEGACY_REASON, ()
    if predicate_result == "not_matched":
        return "not_applicable", _NOT_MATCHED_REASON, ()
    if predicate_result == "missing_evidence":
        return "requires_operator_decision", _MISSING_EVIDENCE_REASON, ()
    if predicate_result == "matched":
        if not capability_ready:
            return "blocked", _CAPABILITY_BLOCKED_REASON, missing_capabilities
        if _weak_status_only(matched_fact_keys, value_maps):
            return "requires_operator_decision", _WEAK_STATUS_REASON, ()
        return "selected", _MATCHED_REASON, ()
    return "blocked", _INVALID_REASON, ()


def _pick_language_variant(
    variants: Sequence[_ResolvedVariant],
    preferred_language: str,
) -> _ResolvedVariant:
    preferred = _normalize_framework_language(preferred_language)
    for lang in (preferred, "en", "any"):
        matches = [v for v in variants if v.language == lang]
        if matches:
            return sorted(matches, key=lambda v: v.framework_id)[0]
    return sorted(variants, key=lambda v: v.framework_id)[0]


def _pick_family_representative(variants: Sequence[_CatalogVariant]) -> _CatalogVariant:
    """Choose a deterministic representative for an inconsistent family."""
    for lang in ("en", "any"):
        matches = [v for v in variants if v.language == lang]
        if matches:
            return sorted(matches, key=lambda v: v.framework_id)[0]
    return sorted(variants, key=lambda v: v.framework_id)[0]


def _catalog_variants(candidates: Sequence[FrameworkCandidate]) -> list[_CatalogVariant]:
    """Deduplicate per-host candidates into one catalog definition per framework."""
    by_id: dict[str, _CatalogVariant] = {}
    for candidate in candidates:
        if candidate.framework_id in by_id:
            continue
        by_id[candidate.framework_id] = _CatalogVariant(
            family_id=candidate.family_id,
            framework_id=candidate.framework_id,
            framework_version=candidate.framework_version,
            language=candidate.language,
            metadata_state=candidate.metadata_state,
            fingerprint=candidate.applicability_fingerprint,
            target_scope=candidate.target_scope,
            target_service=candidate.target_service,
        )
    return sorted(
        by_id.values(),
        key=lambda v: (v.family_id, v.language, v.framework_id, v.framework_version),
    )


def _inconsistent_families(
    catalog: Sequence[_CatalogVariant],
) -> dict[str, _CatalogVariant]:
    """Return family_id → representative for families with divergent fingerprints."""
    by_family: dict[str, list[_CatalogVariant]] = defaultdict(list)
    for variant in catalog:
        if variant.metadata_state == "structured":
            by_family[variant.family_id].append(variant)

    inconsistent: dict[str, _CatalogVariant] = {}
    for family_id, variants in by_family.items():
        fingerprints = {v.fingerprint for v in variants}
        if len(fingerprints) > 1:
            inconsistent[family_id] = _pick_family_representative(variants)
    return inconsistent


def _from_candidate(
    candidate: FrameworkCandidate,
    *,
    client_id: str,
    value_maps: Mapping[str, Mapping[str, object]],
    predicate_result: str | None | object = ...,
    capability_ready: bool | None = None,
    missing_capabilities: tuple[str, ...] | None = None,
    matched_fact_keys: tuple[str, ...] | None = None,
    host_ids: Sequence[str] | None = None,
    host_blocked: bool = False,
    force_target_id: str | None = None,
) -> _ResolvedVariant:
    pred: str | None
    if predicate_result is ...:
        pred = candidate.predicate_result
    else:
        pred = predicate_result  # type: ignore[assignment]

    caps_ready = candidate.capability_ready if capability_ready is None else capability_ready
    missing_caps = (
        candidate.missing_capabilities if missing_capabilities is None else missing_capabilities
    )
    matched = candidate.matched_fact_keys if matched_fact_keys is None else matched_fact_keys
    hosts = list(host_ids) if host_ids is not None else [candidate.host_id]
    maps = [value_maps.get(h, {}) for h in hosts]

    status, reason, out_missing = _decision_fields(
        metadata_state=candidate.metadata_state,
        predicate_result=pred,
        capability_ready=caps_ready,
        missing_capabilities=missing_caps,
        matched_fact_keys=matched,
        value_maps=maps,
        host_blocked=host_blocked,
    )
    if force_target_id is not None:
        target_id = force_target_id
    elif candidate.target_scope == "client":
        target_id = f"client:{client_id}"
    else:
        target_id = _resolve_target_id(candidate, client_id=client_id)
    return _ResolvedVariant(
        target_id=target_id,
        family_id=candidate.family_id,
        framework_id=candidate.framework_id,
        framework_version=candidate.framework_version,
        language=candidate.language,
        metadata_state=candidate.metadata_state,
        fingerprint=candidate.applicability_fingerprint,
        status=status,
        reason=reason,
        missing_capabilities=out_missing,
        structured_valid=candidate.metadata_state == "structured",
    )


def select_frameworks_dynamic(
    inventory: ClientInventory,
    detections: Sequence[TechnologyDetection],
    *,
    agents_dir: Path | str | None = None,
    registry: ToolRegistry | None = None,
    fact_sets: Mapping[str, HostFactSet] | None = None,
    preferred_language: str = "en",
) -> list[FrameworkSelectionDecision]:
    """Select frameworks using declarative applicability metadata.

    When ``fact_sets`` is absent, builds normalized facts from inventory and
    detections (including inventory conflict overlays).
    """
    facts = (
        dict(fact_sets)
        if fact_sets is not None
        else build_inventory_fact_sets(inventory, detections)
    )
    candidates = evaluate_framework_candidates(
        fact_sets=facts,
        agents_dir=agents_dir,
        registry=registry,
    )
    client_id = inventory.client_id
    preferred = _normalize_framework_language(preferred_language)
    value_maps: dict[str, Mapping[str, object]] = {
        host_id: fs.as_value_map() for host_id, fs in facts.items()
    }

    blocked_host_ids = {
        issue.host_id for issue in inventory.issues if issue.level == "error" and issue.host_id
    }
    eligible_host_ids = {host.host_id for host in inventory.hosts_without_errors()}

    catalog = _catalog_variants(candidates)
    inconsistent = _inconsistent_families(catalog)

    decisions: list[FrameworkSelectionDecision] = []

    # Fix 1: one blocked client-level decision per inconsistent family.
    for family_id in sorted(inconsistent):
        representative = inconsistent[family_id]
        decisions.append(
            FrameworkSelectionDecision(
                framework_id=representative.framework_id,
                framework_version=representative.framework_version,
                target_id=f"client:{client_id}",
                reason=_FAMILY_INCONSISTENT_REASON,
                status="blocked",
            )
        )

    inconsistent_family_ids = set(inconsistent)
    # Skip normal resolution for all variants belonging to inconsistent families.
    active_candidates = [c for c in candidates if c.family_id not in inconsistent_family_ids]

    resolved: list[_ResolvedVariant] = []
    client_groups: dict[tuple[str, str, str, str], list[FrameworkCandidate]] = defaultdict(list)

    for candidate in active_candidates:
        if candidate.target_scope == "client":
            key = (
                candidate.framework_id,
                candidate.framework_version,
                candidate.language,
                candidate.family_id,
            )
            client_groups[key].append(candidate)
            continue
        host_blocked = candidate.host_id in blocked_host_ids
        resolved.append(
            _from_candidate(
                candidate,
                client_id=client_id,
                value_maps=value_maps,
                host_blocked=host_blocked,
            )
        )

    for _, group in sorted(client_groups.items(), key=lambda item: item[0]):
        sample = sorted(group, key=lambda c: c.host_id)[0]
        eligible = [c for c in group if c.host_id in eligible_host_ids]

        if not eligible:
            resolved.append(
                _ResolvedVariant(
                    target_id=f"client:{client_id}",
                    family_id=sample.family_id,
                    framework_id=sample.framework_id,
                    framework_version=sample.framework_version,
                    language=sample.language,
                    metadata_state=sample.metadata_state,
                    fingerprint=sample.applicability_fingerprint,
                    status="blocked",
                    reason=_NO_ELIGIBLE_HOSTS_REASON,
                    missing_capabilities=(),
                    structured_valid=sample.metadata_state == "structured",
                )
            )
            continue

        if sample.metadata_state != "structured":
            # Legacy/invalid client-scoped: evaluate against eligible hosts only.
            # Use sample metadata; if invalid keep invalid reason.
            if sample.metadata_state == "invalid":
                status, reason, missing = "blocked", _INVALID_REASON, ()
            else:
                status, reason, missing = (
                    "requires_operator_decision",
                    _LEGACY_REASON,
                    (),
                )
            resolved.append(
                _ResolvedVariant(
                    target_id=f"client:{client_id}",
                    family_id=sample.family_id,
                    framework_id=sample.framework_id,
                    framework_version=sample.framework_version,
                    language=sample.language,
                    metadata_state=sample.metadata_state,
                    fingerprint=sample.applicability_fingerprint,
                    status=status,
                    reason=reason,
                    missing_capabilities=missing,
                    structured_valid=False,
                )
            )
            continue

        pred = _aggregate_client_predicate([c.predicate_result for c in eligible])
        matched = _union_sorted(*(c.matched_fact_keys for c in eligible))
        missing_caps = _union_sorted(*(c.missing_capabilities for c in eligible))
        requires_caps = bool(sample.required_any_capabilities or sample.required_all_capabilities)
        if requires_caps:
            capability_ready = all(c.capability_ready for c in eligible)
        else:
            capability_ready = True
            missing_caps = ()

        resolved.append(
            _from_candidate(
                sample,
                client_id=client_id,
                value_maps=value_maps,
                predicate_result=pred,
                capability_ready=capability_ready,
                missing_capabilities=missing_caps,
                matched_fact_keys=matched,
                host_ids=[c.host_id for c in eligible],
                force_target_id=f"client:{client_id}",
            )
        )

    by_family: dict[tuple[str, str], list[_ResolvedVariant]] = defaultdict(list)
    for item in resolved:
        by_family[(item.target_id, item.family_id)].append(item)

    for (target_id, _family_id), variants in sorted(by_family.items()):
        structured_valid = [v for v in variants if v.structured_valid]
        # Prefer structured variants; suppress legacy production decisions when
        # a valid structured variant exists for the same family/target.
        pool = structured_valid or list(variants)
        picked = _pick_language_variant(pool, preferred)
        decisions.append(
            FrameworkSelectionDecision(
                framework_id=picked.framework_id,
                framework_version=picked.framework_version,
                target_id=target_id,
                reason=picked.reason,
                status=picked.status,  # type: ignore[arg-type]
                missing_capabilities=picked.missing_capabilities,
            )
        )

    family_for = {(v.target_id, v.framework_id): v.family_id for v in resolved}
    for family_id, representative in inconsistent.items():
        family_for[(f"client:{client_id}", representative.framework_id)] = family_id

    decisions.sort(
        key=lambda d: (
            d.target_id,
            family_for.get((d.target_id, d.framework_id), d.framework_id),
            d.framework_id,
            d.status,
        )
    )
    return decisions

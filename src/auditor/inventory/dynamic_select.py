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
    values: list[object] = []
    for value_map in value_maps:
        for key in status_keys:
            if key in value_map:
                values.append(value_map[key])
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
) -> tuple[str, str, tuple[str, ...]]:
    """Return ``(status, reason, missing_capabilities)``."""
    if metadata_state == "invalid" or predicate_result == "invalid":
        return "blocked", _INVALID_REASON, ()
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
    )
    return _ResolvedVariant(
        target_id=_resolve_target_id(candidate, client_id=client_id)
        if candidate.target_scope != "client"
        else f"client:{client_id}",
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

    resolved: list[_ResolvedVariant] = []
    client_groups: dict[tuple[str, str, str, str], list[FrameworkCandidate]] = defaultdict(list)

    for candidate in candidates:
        if candidate.target_scope == "client":
            key = (
                candidate.framework_id,
                candidate.framework_version,
                candidate.language,
                candidate.family_id,
            )
            client_groups[key].append(candidate)
            continue
        resolved.append(_from_candidate(candidate, client_id=client_id, value_maps=value_maps))

    for _, group in sorted(client_groups.items(), key=lambda item: item[0]):
        sample = sorted(group, key=lambda c: c.host_id)[0]
        if sample.metadata_state != "structured":
            resolved.append(
                _from_candidate(
                    sample,
                    client_id=client_id,
                    value_maps=value_maps,
                    host_ids=[c.host_id for c in group],
                )
            )
            continue

        pred = _aggregate_client_predicate([c.predicate_result for c in group])
        matched = _union_sorted(*(c.matched_fact_keys for c in group))
        missing_caps = _union_sorted(*(c.missing_capabilities for c in group))
        requires_caps = bool(sample.required_any_capabilities or sample.required_all_capabilities)
        if requires_caps and pred == "matched":
            capability_ready = all(c.capability_ready for c in group)
        elif requires_caps:
            capability_ready = all(c.capability_ready for c in group)
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
                host_ids=[c.host_id for c in group],
            )
        )

    by_family: dict[tuple[str, str], list[_ResolvedVariant]] = defaultdict(list)
    for item in resolved:
        by_family[(item.target_id, item.family_id)].append(item)

    decisions: list[FrameworkSelectionDecision] = []
    for (target_id, _family_id), variants in sorted(by_family.items()):
        structured_valid = [v for v in variants if v.structured_valid]
        if len(structured_valid) >= 2:
            fingerprints = {v.fingerprint for v in structured_valid}
            if len(fingerprints) > 1:
                representative = sorted(
                    structured_valid,
                    key=lambda v: (v.framework_id, v.language),
                )[0]
                decisions.append(
                    FrameworkSelectionDecision(
                        framework_id=representative.framework_id,
                        framework_version=representative.framework_version,
                        target_id=target_id,
                        reason=_FAMILY_INCONSISTENT_REASON,
                        status="blocked",
                    )
                )
                continue

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
    decisions.sort(
        key=lambda d: (
            d.target_id,
            family_for.get((d.target_id, d.framework_id), d.framework_id),
            d.framework_id,
            d.status,
        )
    )
    return decisions

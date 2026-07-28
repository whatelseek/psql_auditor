"""Build typed capability discovery plans (INPUT005-14).

Never binds tools, invokes adapters, opens sockets, or resolves credentials.
Operation eligibility uses ToolRegistry metadata and host access facts only.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from auditor.domain.applicability import (
    DiscoveryHint,
    FrameworkApplicabilityMeta,
    applicability_fingerprint,
)
from auditor.domain.discovery_plan import (
    CapabilityDiscoveryPlan,
    DiscoveryPlanStep,
    DiscoveryStepStatus,
)
from auditor.domain.inventory import ClientInventory, TechnologyDetection
from auditor.domain.normalized_facts import HostFactSet, build_inventory_fact_sets
from auditor.inventory.framework_candidates import (
    FrameworkCandidate,
    evaluate_framework_candidates,
)
from auditor.inventory.framework_meta import list_frameworks_with_meta
from auditor.tool_registry import ToolManifest, ToolRegistry, get_tool_registry

_ACCESS_SEGMENT_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

_REASON_HINT_NO_FACTS = "Discovery hint does not declare expected facts"
_REASON_NO_HINT = "No typed discovery hint covers the missing fact"
_REASON_UNKNOWN_OP = "Declared discovery operation is unknown"
_REASON_NOT_EXECUTABLE = "Declared discovery operation is not executable"
_REASON_UNAUTHORIZED = "Declared discovery operation is not authorized"
_REASON_CAPABILITY_MISMATCH = "Declared discovery operation capability mismatch"
_REASON_ACCESS_UNAVAILABLE = "Required inventory access is unavailable for the host"
_REASON_HOST_INVALID = "Host has inventory validation errors"
_REASON_PLANNED = "Typed discovery hint matches missing facts with an authorized operation"
_REASON_META_UNAVAILABLE = "Exact framework metadata identity is unavailable"
_REASON_ANY_OF_UNRESOLVED = "No authorized capability alternative is available"

_STATUS_RANK = {
    "planned": 0,
    "requires_operator_decision": 1,
    "blocked": 2,
}

_FAIL_RANK = {
    _REASON_UNKNOWN_OP: 1,
    _REASON_NOT_EXECUTABLE: 2,
    _REASON_UNAUTHORIZED: 3,
    _REASON_CAPABILITY_MISMATCH: 4,
    _REASON_ACCESS_UNAVAILABLE: 5,
}

_PLACEHOLDER_CAPABILITY = "discovery.unspecified"


def _safe_access_segment(segment: str) -> str | None:
    text = str(segment or "").strip().lower()
    if not text:
        return None
    if not _ACCESS_SEGMENT_RE.fullmatch(text):
        return None
    if text.startswith("_") or text.endswith("_") or "__" in text:
        return None
    if "/" in text or "\\" in text or "." in text or ".." in text:
        return None
    return text


def _framework_identity(framework_id: str, framework_version: str) -> str:
    version = str(framework_version or "").strip() or "0"
    return f"{framework_id}@{version}"


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(v) for v in values if str(v)}))


def _sha16(payload: Mapping[str, Any] | Sequence[Any] | str) -> str:
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def framework_catalog_hash(agents_dir: Path | str | None = None) -> str:
    """Secret-free catalog identity (no filesystem paths)."""
    rows: list[str] = []
    for framework, meta in list_frameworks_with_meta(agents_dir):
        rows.append(f"{framework.id}@{framework.version or '0'}:{applicability_fingerprint(meta)}")
    rows.sort()
    return f"fc-{_sha16(rows)}"


def _step_id_for(payload: Mapping[str, Any]) -> str:
    return f"dstep-{_sha16(payload)}"


def _invalid_host_ids(inventory: ClientInventory) -> frozenset[str]:
    healthy = {h.host_id for h in inventory.hosts_without_errors()}
    return frozenset(h.host_id for h in inventory.hosts if h.host_id not in healthy)


def _meta_by_framework(
    agents_dir: Path | str | None,
) -> dict[tuple[str, str], FrameworkApplicabilityMeta]:
    out: dict[tuple[str, str], FrameworkApplicabilityMeta] = {}
    for framework, meta in list_frameworks_with_meta(agents_dir):
        out[(framework.id, framework.version or "")] = meta
    return out


def _candidate_needs_discovery(candidate: FrameworkCandidate) -> bool:
    if candidate.metadata_state != "structured":
        return False
    if candidate.predicate_result in {None, "invalid", "not_matched"}:
        return False
    if candidate.predicate_result == "missing_evidence" and candidate.missing_facts:
        return True
    available = set(candidate.available_capabilities)
    if any(cap not in available for cap in candidate.required_all_capabilities):
        return True
    if candidate.required_any_capabilities and not any(
        cap in available for cap in candidate.required_any_capabilities
    ):
        return True
    return False


def _manifest_host_access_ok(
    manifest: ToolManifest,
    value_map: Mapping[str, object],
) -> bool:
    if not manifest.inventory_access:
        return True
    for raw_segment in manifest.inventory_access:
        segment = _safe_access_segment(str(raw_segment))
        if segment is None:
            return False
        key = f"access.{segment}.available"
        if value_map.get(key) is not True:
            return False
    return True


def _evaluate_operation(
    operation_id: str,
    *,
    capability: str,
    registry: ToolRegistry,
    value_map: Mapping[str, object],
) -> tuple[bool, str]:
    op = str(operation_id or "").strip()
    if not op:
        return False, _REASON_UNKNOWN_OP
    manifest = registry.get(op)
    if manifest is None:
        return False, _REASON_UNKNOWN_OP
    if not manifest.executable:
        return False, _REASON_NOT_EXECUTABLE
    if not registry.is_authorized(op):
        return False, _REASON_UNAUTHORIZED
    if capability not in set(manifest.capabilities):
        return False, _REASON_CAPABILITY_MISMATCH
    if not _manifest_host_access_ok(manifest, value_map):
        return False, _REASON_ACCESS_UNAVAILABLE
    return True, ""


def _resolve_operation(
    operation_ids: Sequence[str],
    *,
    capability: str,
    registry: ToolRegistry,
    value_map: Mapping[str, object],
) -> tuple[str, str, DiscoveryStepStatus]:
    ordered = sorted({str(op).strip() for op in operation_ids if str(op).strip()})
    if not ordered:
        return "", _REASON_UNKNOWN_OP, "blocked"

    best_fail = ""
    best_rank = 99
    for op in ordered:
        ok, reason = _evaluate_operation(
            op,
            capability=capability,
            registry=registry,
            value_map=value_map,
        )
        if ok:
            return op, _REASON_PLANNED, "planned"
        rank = _FAIL_RANK.get(reason, 99)
        if rank < best_rank:
            best_rank = rank
            best_fail = reason
    return "", best_fail or _REASON_UNKNOWN_OP, "blocked"


@dataclass(frozen=True, slots=True)
class _Alt:
    status: DiscoveryStepStatus
    reason: str
    capability: str
    operation_id: str
    expected_facts: tuple[str, ...]
    covered_facts: tuple[str, ...]
    capability_options: tuple[str, ...] = ()


def _alt_sort_key(alt: _Alt) -> tuple[Any, ...]:
    return (
        _STATUS_RANK.get(alt.status, 99),
        alt.capability,
        alt.operation_id,
        alt.expected_facts,
        alt.covered_facts,
        alt.capability_options,
    )


def _evaluate_hint(
    hint: DiscoveryHint,
    *,
    covered_facts: Sequence[str],
    registry: ToolRegistry,
    value_map: Mapping[str, object],
    capability_options: Sequence[str] = (),
) -> _Alt:
    if not hint.expected_facts:
        return _Alt(
            status="requires_operator_decision",
            reason=_REASON_HINT_NO_FACTS,
            capability=hint.capability,
            operation_id="",
            expected_facts=(),
            covered_facts=_sorted_unique(covered_facts),
            capability_options=_sorted_unique(capability_options),
        )
    op_id, reason, status = _resolve_operation(
        hint.operation_ids,
        capability=hint.capability,
        registry=registry,
        value_map=value_map,
    )
    return _Alt(
        status=status,
        reason=reason,
        capability=hint.capability,
        operation_id=op_id if status == "planned" else "",
        expected_facts=_sorted_unique(hint.expected_facts),
        covered_facts=_sorted_unique(covered_facts),
        capability_options=_sorted_unique(capability_options),
    )


def _draft_step(
    *,
    host_id: str,
    capability: str,
    operation_id: str,
    tool_id: str,
    expected_facts: Sequence[str],
    missing_facts: Sequence[str],
    framework_identity: str,
    status: DiscoveryStepStatus,
    reason: str,
    capability_options: Sequence[str] = (),
) -> dict[str, Any]:
    return {
        "host_id": host_id,
        "capability": capability,
        "capability_options": _sorted_unique(capability_options),
        "operation_id": operation_id,
        "tool_id": tool_id,
        "expected_facts": _sorted_unique(expected_facts),
        "missing_facts": _sorted_unique(missing_facts),
        "requested_by_frameworks": (framework_identity,),
        "status": status,
        "reason": reason,
    }


def _draft_from_alt(
    alt: _Alt,
    *,
    host_id: str,
    framework_identity: str,
    missing_facts: Sequence[str],
) -> dict[str, Any]:
    return _draft_step(
        host_id=host_id,
        capability=alt.capability,
        operation_id=alt.operation_id if alt.status == "planned" else "",
        tool_id=alt.operation_id if alt.status == "planned" else "",
        expected_facts=alt.expected_facts,
        missing_facts=missing_facts,
        framework_identity=framework_identity,
        status=alt.status,
        reason=alt.reason,
        capability_options=alt.capability_options,
    )


def _merge_drafts(drafts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], dict[str, Any]] = {}
    order: list[tuple[Any, ...]] = []
    for draft in drafts:
        key = (
            draft["host_id"],
            draft["capability"],
            draft["operation_id"],
            draft["expected_facts"],
            draft["missing_facts"],
            draft["status"],
            draft["capability_options"],
        )
        if key not in buckets:
            buckets[key] = dict(draft)
            order.append(key)
            continue
        existing = buckets[key]
        existing["requested_by_frameworks"] = _sorted_unique(
            [
                *existing["requested_by_frameworks"],
                *draft["requested_by_frameworks"],
            ]
        )
        if draft["status"] == "planned":
            existing["reason"] = draft["reason"]
    merged = [buckets[k] for k in order]
    merged.sort(
        key=lambda d: (
            d["host_id"],
            d["capability"],
            d["operation_id"],
            d["missing_facts"],
            d["expected_facts"],
            d["status"],
            d["capability_options"],
            d["requested_by_frameworks"],
        )
    )
    return merged


def _finalize_steps(drafts: list[dict[str, Any]]) -> tuple[DiscoveryPlanStep, ...]:
    steps: list[DiscoveryPlanStep] = []
    for draft in drafts:
        identity = {
            "capability": draft["capability"],
            "capability_options": list(draft["capability_options"]),
            "expected_facts": list(draft["expected_facts"]),
            "host_id": draft["host_id"],
            "missing_facts": list(draft["missing_facts"]),
            "operation_id": draft["operation_id"],
            "reason": draft["reason"],
            "requested_by_frameworks": list(draft["requested_by_frameworks"]),
            "status": draft["status"],
            "tool_id": draft["tool_id"],
        }
        steps.append(
            DiscoveryPlanStep(
                step_id=_step_id_for(identity),
                host_id=str(draft["host_id"]),
                capability=str(draft["capability"]),
                capability_options=tuple(draft["capability_options"]),
                operation_id=str(draft["operation_id"]),
                tool_id=str(draft["tool_id"]),
                expected_facts=tuple(draft["expected_facts"]),
                missing_facts=tuple(draft["missing_facts"]),
                requested_by_frameworks=tuple(draft["requested_by_frameworks"]),
                status=draft["status"],
                reason=str(draft["reason"]),
            )
        )
    return tuple(steps)


def _plan_questions(steps: Sequence[DiscoveryPlanStep]) -> tuple[str, ...]:
    questions: list[str] = []
    seen: set[str] = set()
    for step in steps:
        if step.status not in {"blocked", "requires_operator_decision"}:
            continue
        text = f"Resolve discovery step {step.step_id} for {step.host_id}: {step.reason}"
        if text in seen:
            continue
        seen.add(text)
        questions.append(text)
    return tuple(questions)


def _identity_payload(
    *,
    client_id: str,
    inventory_version_id: str,
    inventory_content_hash: str,
    framework_catalog_hash: str,
    tool_catalog_hash: str,
    capability_policy_hash: str,
    steps: Sequence[DiscoveryPlanStep],
    unresolved_questions: Sequence[str],
) -> dict[str, Any]:
    return {
        "capability_policy_hash": capability_policy_hash,
        "client_id": client_id,
        "framework_catalog_hash": framework_catalog_hash,
        "inventory_content_hash": inventory_content_hash,
        "inventory_version_id": inventory_version_id,
        "steps": [
            {
                "capability": s.capability,
                "capability_options": list(s.capability_options),
                "expected_facts": list(s.expected_facts),
                "host_id": s.host_id,
                "missing_facts": list(s.missing_facts),
                "operation_id": s.operation_id,
                "reason": s.reason,
                "requested_by_frameworks": list(s.requested_by_frameworks),
                "status": s.status,
                "step_id": s.step_id,
                "tool_id": s.tool_id,
            }
            for s in steps
        ],
        "tool_catalog_hash": tool_catalog_hash,
        "unresolved_questions": list(unresolved_questions),
    }


def _emit_invalid_host_blocks(
    candidate: FrameworkCandidate,
    *,
    identity: str,
) -> list[dict[str, Any]]:
    """Fix 1: block all discovery needs before hint/operation evaluation."""
    drafts: list[dict[str, Any]] = []
    if candidate.predicate_result == "missing_evidence" and candidate.missing_facts:
        drafts.append(
            _draft_step(
                host_id=candidate.host_id,
                capability=_PLACEHOLDER_CAPABILITY,
                operation_id="",
                tool_id="",
                expected_facts=(),
                missing_facts=candidate.missing_facts,
                framework_identity=identity,
                status="blocked",
                reason=_REASON_HOST_INVALID,
            )
        )
    available = set(candidate.available_capabilities)
    for cap in candidate.required_all_capabilities:
        if cap in available:
            continue
        drafts.append(
            _draft_step(
                host_id=candidate.host_id,
                capability=cap,
                operation_id="",
                tool_id="",
                expected_facts=(),
                missing_facts=(),
                framework_identity=identity,
                status="blocked",
                reason=_REASON_HOST_INVALID,
            )
        )
    any_group = _sorted_unique(candidate.required_any_capabilities)
    if any_group and not any(cap in available for cap in any_group):
        drafts.append(
            _draft_step(
                host_id=candidate.host_id,
                capability=any_group[0],
                operation_id="",
                tool_id="",
                expected_facts=(),
                missing_facts=(),
                framework_identity=identity,
                status="blocked",
                reason=_REASON_HOST_INVALID,
                capability_options=any_group,
            )
        )
    return drafts


def _select_fact_alternatives(
    *,
    host_id: str,
    missing_facts: Sequence[str],
    hints: Sequence[DiscoveryHint],
    framework_identity: str,
    registry: ToolRegistry,
    value_map: Mapping[str, object],
) -> list[dict[str, Any]]:
    """Fix 2: evaluate all alternatives before consuming any missing fact."""
    remaining = set(missing_facts)
    if not remaining:
        return []

    concrete = [h for h in hints if h.expected_facts]
    empty_hints = [h for h in hints if not h.expected_facts]

    alternatives: list[_Alt] = []
    for hint in concrete:
        hint_covered = _sorted_unique(set(hint.expected_facts) & remaining)
        if not hint_covered:
            continue
        alternatives.append(
            _evaluate_hint(
                hint,
                covered_facts=hint_covered,
                registry=registry,
                value_map=value_map,
            )
        )

    drafts: list[dict[str, Any]] = []
    covered_facts: set[str] = set()

    planned = sorted(
        [a for a in alternatives if a.status == "planned"],
        key=_alt_sort_key,
    )
    for alt in planned:
        still = _sorted_unique(set(alt.covered_facts) - covered_facts)
        if not still:
            continue
        drafts.append(
            _draft_from_alt(
                alt,
                host_id=host_id,
                framework_identity=framework_identity,
                missing_facts=still,
            )
        )
        covered_facts.update(still)

    leftover = remaining - covered_facts
    while leftover:
        fact = sorted(leftover)[0]
        candidates = [a for a in alternatives if fact in a.covered_facts and a.status != "planned"]
        if candidates:
            best = sorted(candidates, key=_alt_sort_key)[0]
            still = _sorted_unique(set(best.covered_facts) & leftover)
            drafts.append(
                _draft_from_alt(
                    best,
                    host_id=host_id,
                    framework_identity=framework_identity,
                    missing_facts=still,
                )
            )
            leftover -= set(still)
            continue

        if empty_hints:
            hint = sorted(empty_hints, key=lambda h: (h.capability, h.operation_ids))[0]
            still = _sorted_unique(leftover)
            drafts.append(
                _draft_step(
                    host_id=host_id,
                    capability=hint.capability,
                    operation_id="",
                    tool_id="",
                    expected_facts=(),
                    missing_facts=still,
                    framework_identity=framework_identity,
                    status="requires_operator_decision",
                    reason=_REASON_HINT_NO_FACTS,
                )
            )
            leftover.clear()
            continue

        drafts.append(
            _draft_step(
                host_id=host_id,
                capability=_PLACEHOLDER_CAPABILITY,
                operation_id="",
                tool_id="",
                expected_facts=(),
                missing_facts=(fact,),
                framework_identity=framework_identity,
                status="requires_operator_decision",
                reason=_REASON_NO_HINT,
            )
        )
        leftover.discard(fact)

    return drafts


def _resolve_capability_hints(
    *,
    host_id: str,
    capability: str,
    hints: Sequence[DiscoveryHint],
    framework_identity: str,
    registry: ToolRegistry,
    value_map: Mapping[str, object],
    capability_options: Sequence[str] = (),
) -> dict[str, Any]:
    """Resolve one capability requirement against typed hints."""
    matching = [h for h in hints if h.capability == capability]
    if not matching:
        return _draft_step(
            host_id=host_id,
            capability=capability,
            operation_id="",
            tool_id="",
            expected_facts=(),
            missing_facts=(),
            framework_identity=framework_identity,
            status="requires_operator_decision",
            reason=_REASON_NO_HINT,
            capability_options=capability_options,
        )

    alts: list[_Alt] = []
    for hint in matching:
        if not hint.expected_facts:
            alts.append(
                _Alt(
                    status="requires_operator_decision",
                    reason=_REASON_HINT_NO_FACTS,
                    capability=hint.capability,
                    operation_id="",
                    expected_facts=(),
                    covered_facts=(),
                    capability_options=_sorted_unique(capability_options),
                )
            )
            continue
        alts.append(
            _evaluate_hint(
                hint,
                covered_facts=(),
                registry=registry,
                value_map=value_map,
                capability_options=capability_options,
            )
        )
    best = sorted(alts, key=_alt_sort_key)[0]
    return _draft_from_alt(
        best,
        host_id=host_id,
        framework_identity=framework_identity,
        missing_facts=(),
    )


def _emit_capability_work(
    candidate: FrameworkCandidate,
    *,
    hints: Sequence[DiscoveryHint],
    identity: str,
    registry: ToolRegistry,
    value_map: Mapping[str, object],
) -> list[dict[str, Any]]:
    """Fix 3: resolve all_of independently and any_of as one alternative group."""
    drafts: list[dict[str, Any]] = []
    available = set(candidate.available_capabilities)

    for cap in candidate.required_all_capabilities:
        if cap in available:
            continue
        drafts.append(
            _resolve_capability_hints(
                host_id=candidate.host_id,
                capability=cap,
                hints=hints,
                framework_identity=identity,
                registry=registry,
                value_map=value_map,
            )
        )

    any_group = _sorted_unique(candidate.required_any_capabilities)
    if any_group and not any(cap in available for cap in any_group):
        alts: list[_Alt] = []
        for cap in any_group:
            matching = [h for h in hints if h.capability == cap]
            if not matching:
                alts.append(
                    _Alt(
                        status="requires_operator_decision",
                        reason=_REASON_NO_HINT,
                        capability=cap,
                        operation_id="",
                        expected_facts=(),
                        covered_facts=(),
                        capability_options=any_group,
                    )
                )
                continue
            for hint in matching:
                if not hint.expected_facts:
                    alts.append(
                        _Alt(
                            status="requires_operator_decision",
                            reason=_REASON_HINT_NO_FACTS,
                            capability=cap,
                            operation_id="",
                            expected_facts=(),
                            covered_facts=(),
                            capability_options=any_group,
                        )
                    )
                    continue
                alts.append(
                    _evaluate_hint(
                        hint,
                        covered_facts=(),
                        registry=registry,
                        value_map=value_map,
                        capability_options=any_group,
                    )
                )
        if not alts:
            drafts.append(
                _draft_step(
                    host_id=candidate.host_id,
                    capability=any_group[0],
                    operation_id="",
                    tool_id="",
                    expected_facts=(),
                    missing_facts=(),
                    framework_identity=identity,
                    status="requires_operator_decision",
                    reason=_REASON_NO_HINT,
                    capability_options=any_group,
                )
            )
        else:
            best = sorted(alts, key=_alt_sort_key)[0]
            if best.status != "planned" and best.reason == _REASON_NO_HINT:
                best = _Alt(
                    status="requires_operator_decision",
                    reason=_REASON_ANY_OF_UNRESOLVED
                    if all(a.status == "blocked" for a in alts)
                    else best.reason,
                    capability=best.capability,
                    operation_id="",
                    expected_facts=best.expected_facts,
                    covered_facts=(),
                    capability_options=any_group,
                )
            elif best.status == "blocked":
                best = _Alt(
                    status="blocked",
                    reason=best.reason,
                    capability=best.capability,
                    operation_id="",
                    expected_facts=best.expected_facts,
                    covered_facts=(),
                    capability_options=any_group,
                )
            drafts.append(
                _draft_from_alt(
                    best,
                    host_id=candidate.host_id,
                    framework_identity=identity,
                    missing_facts=(),
                )
            )
    return drafts


def build_capability_discovery_plan(
    inventory: ClientInventory,
    detections: Sequence[TechnologyDetection],
    *,
    agents_dir: Path | str | None = None,
    registry: ToolRegistry | None = None,
    host_facts: Mapping[str, HostFactSet] | None = None,
) -> CapabilityDiscoveryPlan:
    """Build a deterministic capability discovery plan from typed metadata only."""
    tool_registry = registry if registry is not None else get_tool_registry()
    fact_sets = (
        dict(host_facts)
        if host_facts is not None
        else build_inventory_fact_sets(inventory, detections)
    )
    candidates = evaluate_framework_candidates(
        fact_sets=fact_sets,
        agents_dir=agents_dir,
        registry=tool_registry,
    )
    meta_index = _meta_by_framework(agents_dir)
    catalog_hash = framework_catalog_hash(agents_dir)
    invalid_hosts = _invalid_host_ids(inventory)

    drafts: list[dict[str, Any]] = []
    for candidate in candidates:
        if not _candidate_needs_discovery(candidate):
            continue

        identity = _framework_identity(candidate.framework_id, candidate.framework_version)
        host_invalid = candidate.host_id in invalid_hosts

        # Fix 1: invalid hosts are blocked before hint/operation evaluation.
        if host_invalid:
            drafts.extend(_emit_invalid_host_blocks(candidate, identity=identity))
            continue

        # Fix 5: exact framework identity only — no id-only fallback.
        meta = meta_index.get((candidate.framework_id, candidate.framework_version))
        if meta is None:
            drafts.append(
                _draft_step(
                    host_id=candidate.host_id,
                    capability=_PLACEHOLDER_CAPABILITY,
                    operation_id="",
                    tool_id="",
                    expected_facts=(),
                    missing_facts=candidate.missing_facts
                    if candidate.predicate_result == "missing_evidence"
                    else (),
                    framework_identity=identity,
                    status="requires_operator_decision",
                    reason=_REASON_META_UNAVAILABLE,
                )
            )
            continue

        hints = tuple(
            sorted(
                meta.discovery_hints,
                key=lambda h: (h.capability, h.expected_facts, h.operation_ids),
            )
        )
        value_map = fact_sets.get(candidate.host_id)
        values: Mapping[str, object] = value_map.as_value_map() if value_map is not None else {}

        if candidate.predicate_result == "missing_evidence" and candidate.missing_facts:
            drafts.extend(
                _select_fact_alternatives(
                    host_id=candidate.host_id,
                    missing_facts=candidate.missing_facts,
                    hints=hints,
                    framework_identity=identity,
                    registry=tool_registry,
                    value_map=values,
                )
            )

        drafts.extend(
            _emit_capability_work(
                candidate,
                hints=hints,
                identity=identity,
                registry=tool_registry,
                value_map=values,
            )
        )

    merged = _merge_drafts(drafts)
    steps = _finalize_steps(merged)
    questions = _plan_questions(steps)
    hashes = tool_registry.snapshot_hashes()
    tool_catalog_hash = str(hashes.get("tool_catalog_hash") or "")
    policy_hash = str(hashes.get("capability_policy_hash") or "")
    payload = _identity_payload(
        client_id=inventory.client_id,
        inventory_version_id=inventory.version.version_id,
        inventory_content_hash=inventory.version.content_hash,
        framework_catalog_hash=catalog_hash,
        tool_catalog_hash=tool_catalog_hash,
        capability_policy_hash=policy_hash,
        steps=steps,
        unresolved_questions=questions,
    )
    digest = _sha16(payload)
    return CapabilityDiscoveryPlan(
        discovery_plan_id=f"dplan-{digest}",
        discovery_plan_hash=f"dph-{digest}",
        client_id=inventory.client_id,
        inventory_version_id=inventory.version.version_id,
        inventory_content_hash=inventory.version.content_hash,
        framework_catalog_hash=catalog_hash,
        tool_catalog_hash=tool_catalog_hash,
        capability_policy_hash=policy_hash,
        steps=steps,
        unresolved_questions=questions,
        requires_confirmation=True,
    )

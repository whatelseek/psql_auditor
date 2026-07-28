"""Build typed capability discovery plans (INPUT005-14).

Never binds tools, invokes adapters, opens sockets, or resolves credentials.
Operation eligibility uses ToolRegistry metadata and host access facts only.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from auditor.domain.applicability import DiscoveryHint, FrameworkApplicabilityMeta
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

# Stable generic reasons — never embed secrets, notes, purpose, or parser text.
_REASON_HINT_NO_FACTS = "Discovery hint does not declare expected facts"
_REASON_NO_HINT = "No typed discovery hint covers the missing fact"
_REASON_UNKNOWN_OP = "Declared discovery operation is unknown"
_REASON_NOT_EXECUTABLE = "Declared discovery operation is not executable"
_REASON_UNAUTHORIZED = "Declared discovery operation is not authorized"
_REASON_CAPABILITY_MISMATCH = "Declared discovery operation capability mismatch"
_REASON_ACCESS_UNAVAILABLE = "Required inventory access is unavailable for the host"
_REASON_HOST_INVALID = "Host has inventory validation errors"
_REASON_PLANNED = "Typed discovery hint matches missing facts with an authorized operation"

_FAIL_RANK = {
    _REASON_UNKNOWN_OP: 1,
    _REASON_NOT_EXECUTABLE: 2,
    _REASON_UNAUTHORIZED: 3,
    _REASON_CAPABILITY_MISMATCH: 4,
    _REASON_ACCESS_UNAVAILABLE: 5,
}


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
    return f"{framework_id}@{framework_version}"


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(v) for v in values if str(v)}))


def _sha16(payload: Mapping[str, Any] | Sequence[Any] | str) -> str:
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


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
        key = (framework.id, framework.version or "")
        out[key] = meta
    return out


def _candidate_needs_discovery(candidate: FrameworkCandidate) -> bool:
    if candidate.metadata_state != "structured":
        return False
    if candidate.predicate_result in {None, "invalid", "not_matched"}:
        return False
    if candidate.predicate_result == "missing_evidence" and candidate.missing_facts:
        return True
    if candidate.missing_capabilities:
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
    """Return (eligible, failure_reason). Failure reasons follow precedence ranks."""
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
    """Pick first lexically eligible op, or one blocked reason by precedence."""
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
) -> dict[str, Any]:
    return {
        "host_id": host_id,
        "capability": capability,
        "operation_id": operation_id,
        "tool_id": tool_id,
        "expected_facts": _sorted_unique(expected_facts),
        "missing_facts": _sorted_unique(missing_facts),
        "requested_by_frameworks": (framework_identity,),
        "status": status,
        "reason": reason,
    }


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
        )
        if key not in buckets:
            buckets[key] = dict(draft)
            order.append(key)
            continue
        existing = buckets[key]
        frameworks = _sorted_unique(
            [
                *existing["requested_by_frameworks"],
                *draft["requested_by_frameworks"],
            ]
        )
        existing["requested_by_frameworks"] = frameworks
        # Prefer the more specific planned reason when merging identical keys.
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
            d["requested_by_frameworks"],
        )
    )
    return merged


def _finalize_steps(drafts: list[dict[str, Any]]) -> tuple[DiscoveryPlanStep, ...]:
    steps: list[DiscoveryPlanStep] = []
    for draft in drafts:
        identity = {
            "host_id": draft["host_id"],
            "capability": draft["capability"],
            "operation_id": draft["operation_id"],
            "tool_id": draft["tool_id"],
            "expected_facts": list(draft["expected_facts"]),
            "missing_facts": list(draft["missing_facts"]),
            "requested_by_frameworks": list(draft["requested_by_frameworks"]),
            "status": draft["status"],
            "reason": draft["reason"],
        }
        steps.append(
            DiscoveryPlanStep(
                step_id=_step_id_for(identity),
                host_id=str(draft["host_id"]),
                capability=str(draft["capability"]),
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
    tool_catalog_hash: str,
    capability_policy_hash: str,
    steps: Sequence[DiscoveryPlanStep],
    unresolved_questions: Sequence[str],
) -> dict[str, Any]:
    return {
        "capability_policy_hash": capability_policy_hash,
        "client_id": client_id,
        "inventory_content_hash": inventory_content_hash,
        "inventory_version_id": inventory_version_id,
        "steps": [
            {
                "capability": s.capability,
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


def _emit_for_hint(
    *,
    host_id: str,
    hint: DiscoveryHint,
    missing_facts: Sequence[str],
    framework_identity: str,
    registry: ToolRegistry,
    value_map: Mapping[str, object],
    host_invalid: bool,
) -> list[dict[str, Any]]:
    """Build draft steps for one typed hint against remaining missing facts."""
    if not hint.expected_facts:
        return [
            _draft_step(
                host_id=host_id,
                capability=hint.capability,
                operation_id="",
                tool_id="",
                expected_facts=(),
                missing_facts=missing_facts,
                framework_identity=framework_identity,
                status="requires_operator_decision",
                reason=_REASON_HINT_NO_FACTS,
            )
        ]

    covered = _sorted_unique(set(hint.expected_facts) & set(missing_facts))
    if not covered:
        return []

    if host_invalid:
        return [
            _draft_step(
                host_id=host_id,
                capability=hint.capability,
                operation_id="",
                tool_id="",
                expected_facts=hint.expected_facts,
                missing_facts=covered,
                framework_identity=framework_identity,
                status="blocked",
                reason=_REASON_HOST_INVALID,
            )
        ]

    op_id, reason, status = _resolve_operation(
        hint.operation_ids,
        capability=hint.capability,
        registry=registry,
        value_map=value_map,
    )
    tool_id = op_id if status == "planned" else ""
    return [
        _draft_step(
            host_id=host_id,
            capability=hint.capability,
            operation_id=op_id if status == "planned" else "",
            tool_id=tool_id,
            expected_facts=hint.expected_facts,
            missing_facts=covered,
            framework_identity=framework_identity,
            status=status,
            reason=reason,
        )
    ]


def _emit_for_capability(
    *,
    host_id: str,
    hint: DiscoveryHint,
    framework_identity: str,
    registry: ToolRegistry,
    value_map: Mapping[str, object],
    host_invalid: bool,
) -> list[dict[str, Any]]:
    """Build draft steps for a missing-capability hint."""
    if not hint.expected_facts and not hint.operation_ids:
        return [
            _draft_step(
                host_id=host_id,
                capability=hint.capability,
                operation_id="",
                tool_id="",
                expected_facts=(),
                missing_facts=(),
                framework_identity=framework_identity,
                status="requires_operator_decision",
                reason=_REASON_HINT_NO_FACTS,
            )
        ]
    if not hint.expected_facts:
        # Capability gap with ops but no declared facts → operator, do not assume coverage.
        return [
            _draft_step(
                host_id=host_id,
                capability=hint.capability,
                operation_id="",
                tool_id="",
                expected_facts=(),
                missing_facts=(),
                framework_identity=framework_identity,
                status="requires_operator_decision",
                reason=_REASON_HINT_NO_FACTS,
            )
        ]

    if host_invalid:
        return [
            _draft_step(
                host_id=host_id,
                capability=hint.capability,
                operation_id="",
                tool_id="",
                expected_facts=hint.expected_facts,
                missing_facts=(),
                framework_identity=framework_identity,
                status="blocked",
                reason=_REASON_HOST_INVALID,
            )
        ]

    op_id, reason, status = _resolve_operation(
        hint.operation_ids,
        capability=hint.capability,
        registry=registry,
        value_map=value_map,
    )
    return [
        _draft_step(
            host_id=host_id,
            capability=hint.capability,
            operation_id=op_id if status == "planned" else "",
            tool_id=op_id if status == "planned" else "",
            expected_facts=hint.expected_facts,
            missing_facts=(),
            framework_identity=framework_identity,
            status=status,
            reason=reason,
        )
    ]


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
    invalid_hosts = _invalid_host_ids(inventory)

    drafts: list[dict[str, Any]] = []
    for candidate in candidates:
        if not _candidate_needs_discovery(candidate):
            continue
        meta = meta_index.get((candidate.framework_id, candidate.framework_version))
        if meta is None:
            # Fall back to id-only lookup when version keys drift.
            for (fid, _ver), item in meta_index.items():
                if fid == candidate.framework_id:
                    meta = item
                    break
        hints: tuple[DiscoveryHint, ...] = meta.discovery_hints if meta is not None else ()
        identity = _framework_identity(candidate.framework_id, candidate.framework_version)
        value_map = fact_sets.get(candidate.host_id)
        values: Mapping[str, object] = value_map.as_value_map() if value_map is not None else {}
        host_invalid = candidate.host_id in invalid_hosts

        remaining = set(candidate.missing_facts)
        # Stable hint order: capability, expected_facts, operation_ids.
        ordered_hints = sorted(
            hints,
            key=lambda h: (
                h.capability,
                h.expected_facts,
                h.operation_ids,
            ),
        )

        if candidate.predicate_result == "missing_evidence" and remaining:
            empty_fact_hints = [h for h in ordered_hints if not h.expected_facts]
            concrete_hints = [h for h in ordered_hints if h.expected_facts]
            for hint in concrete_hints:
                if not remaining:
                    break
                produced = _emit_for_hint(
                    host_id=candidate.host_id,
                    hint=hint,
                    missing_facts=tuple(sorted(remaining)),
                    framework_identity=identity,
                    registry=tool_registry,
                    value_map=values,
                    host_invalid=host_invalid,
                )
                if not produced:
                    continue
                drafts.extend(produced)
                for step in produced:
                    remaining -= set(step["missing_facts"])

            if remaining and empty_fact_hints:
                # One operator step for ambiguous hints; consumes leftover facts.
                hint = empty_fact_hints[0]
                drafts.append(
                    _draft_step(
                        host_id=candidate.host_id,
                        capability=hint.capability,
                        operation_id="",
                        tool_id="",
                        expected_facts=(),
                        missing_facts=tuple(sorted(remaining)),
                        framework_identity=identity,
                        status="requires_operator_decision",
                        reason=_REASON_HINT_NO_FACTS,
                    )
                )
                remaining.clear()

            for fact in sorted(remaining):
                drafts.append(
                    _draft_step(
                        host_id=candidate.host_id,
                        capability="discovery",
                        operation_id="",
                        tool_id="",
                        expected_facts=(),
                        missing_facts=(fact,),
                        framework_identity=identity,
                        status="requires_operator_decision",
                        reason=_REASON_NO_HINT,
                    )
                )

        if candidate.missing_capabilities:
            missing_caps = set(candidate.missing_capabilities)
            matched_caps: set[str] = set()
            for hint in ordered_hints:
                if hint.capability not in missing_caps:
                    continue
                matched_caps.add(hint.capability)
                drafts.extend(
                    _emit_for_capability(
                        host_id=candidate.host_id,
                        hint=hint,
                        framework_identity=identity,
                        registry=tool_registry,
                        value_map=values,
                        host_invalid=host_invalid,
                    )
                )
            for cap in sorted(missing_caps - matched_caps):
                drafts.append(
                    _draft_step(
                        host_id=candidate.host_id,
                        capability=cap,
                        operation_id="",
                        tool_id="",
                        expected_facts=(),
                        missing_facts=(),
                        framework_identity=identity,
                        status="requires_operator_decision",
                        reason=_REASON_NO_HINT,
                    )
                )

    merged = _merge_drafts(drafts)
    steps = _finalize_steps(merged)
    questions = _plan_questions(steps)
    hashes = tool_registry.snapshot_hashes()
    catalog_hash = str(hashes.get("tool_catalog_hash") or "")
    policy_hash = str(hashes.get("capability_policy_hash") or "")
    payload = _identity_payload(
        client_id=inventory.client_id,
        inventory_version_id=inventory.version.version_id,
        inventory_content_hash=inventory.version.content_hash,
        tool_catalog_hash=catalog_hash,
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
        tool_catalog_hash=catalog_hash,
        capability_policy_hash=policy_hash,
        steps=steps,
        unresolved_questions=questions,
        requires_confirmation=True,
    )

"""Framework candidate matrix evaluation (INPUT005-12).

Evaluates every host/framework pair against normalized facts and authorized
capabilities. Never binds or invokes tools.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from auditor.domain.applicability import (
    PredicateResult,
    TargetScope,
    applicability_fingerprint,
    evaluate_applicability,
)
from auditor.domain.normalized_facts import HostFactSet
from auditor.inventory.framework_meta import list_frameworks_with_meta
from auditor.tool_registry import ToolRegistry, get_tool_registry

CandidateMetadataState = Literal[
    "structured",
    "legacy",
    "invalid",
]

_ACCESS_SEGMENT_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


class FrameworkCandidate(BaseModel):
    """Secret-free evaluation of one host against one framework variant."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    host_id: StrictStr = Field(min_length=1)

    framework_id: StrictStr = Field(min_length=1)
    framework_version: StrictStr = ""
    family_id: StrictStr = ""
    language: StrictStr = "any"

    metadata_state: CandidateMetadataState
    predicate_result: PredicateResult | None

    target_scope: TargetScope | None = None
    target_service: StrictStr = ""

    matched_fact_keys: tuple[str, ...] = ()
    missing_facts: tuple[str, ...] = ()

    required_any_capabilities: tuple[str, ...] = ()
    required_all_capabilities: tuple[str, ...] = ()
    available_capabilities: tuple[str, ...] = ()
    missing_capabilities: tuple[str, ...] = ()
    capability_ready: bool = False

    applicability_fingerprint: StrictStr = ""


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


def available_capabilities_for_host(
    value_map: Mapping[str, object],
    registry: ToolRegistry,
) -> tuple[str, ...]:
    """Capabilities from authorized executable tools available on this host."""
    caps: set[str] = set()
    for manifest in registry.authorized_tools():
        if not manifest.executable:
            continue
        access_ok = True
        for raw_segment in manifest.inventory_access:
            segment = _safe_access_segment(raw_segment)
            if segment is None:
                access_ok = False
                break
            key = f"access.{segment}.available"
            if value_map.get(key) is not True:
                access_ok = False
                break
        if access_ok:
            caps.update(str(c) for c in manifest.capabilities if c)
    return tuple(sorted(caps))


def _capability_readiness(
    *,
    any_of: tuple[str, ...],
    all_of: tuple[str, ...],
    available: set[str],
) -> tuple[bool, tuple[str, ...]]:
    missing: list[str] = []
    for cap in all_of:
        if cap not in available:
            missing.append(cap)
    if any_of:
        if not any(cap in available for cap in any_of):
            missing.extend(any_of)
    ready = not missing
    return ready, tuple(sorted(set(missing)))


def _finalize_required_facts(
    *,
    predicate_result: PredicateResult,
    eval_missing: tuple[str, ...],
    required_facts: tuple[str, ...],
    value_map: Mapping[str, object],
) -> tuple[PredicateResult, tuple[str, ...]]:
    req_missing = tuple(sorted({f for f in required_facts if f not in value_map}))
    if predicate_result == "not_matched":
        return "not_matched", tuple(sorted(set(eval_missing) | set(req_missing)))
    if predicate_result == "invalid":
        return "invalid", tuple(sorted(set(eval_missing) | set(req_missing)))
    merged = tuple(sorted(set(eval_missing) | set(req_missing)))
    if predicate_result == "matched" and req_missing:
        return "missing_evidence", merged
    if predicate_result == "missing_evidence":
        return "missing_evidence", merged
    return predicate_result, merged


def evaluate_framework_candidates(
    *,
    fact_sets: Mapping[str, HostFactSet],
    agents_dir: Path | str | None = None,
    registry: ToolRegistry | None = None,
) -> list[FrameworkCandidate]:
    """Evaluate every supplied host fact set against every catalog framework.

    Does not bind tools. Does not invoke tools. Does not import tool adapters.
    """
    tool_registry = registry if registry is not None else get_tool_registry()
    catalog = list_frameworks_with_meta(agents_dir)
    hosts = sorted(fact_sets.items(), key=lambda item: item[0])
    candidates: list[FrameworkCandidate] = []

    for host_id, fact_set in hosts:
        value_map = fact_set.as_value_map()
        available = available_capabilities_for_host(value_map, tool_registry)
        available_set = set(available)

        for framework, meta in catalog:
            family_id = framework.family_id or framework.id
            language = framework.language or "any"
            version = framework.version or ""
            fingerprint = applicability_fingerprint(meta)

            required_any = tuple(meta.required_capabilities.any_of)
            required_all = tuple(meta.required_capabilities.all_of)

            if meta.has_structured_applicability and not meta.metadata_valid:
                metadata_state: CandidateMetadataState = "invalid"
                predicate_result: PredicateResult | None = "invalid"
                target_scope: TargetScope | None = None
                target_service = ""
                matched: tuple[str, ...] = ()
                missing_facts: tuple[str, ...] = ()
                cap_ready = False
                missing_caps: tuple[str, ...] = ()
            elif not framework.executable:
                metadata_state = "invalid"
                predicate_result = "invalid"
                target_scope = None
                target_service = ""
                matched = ()
                missing_facts = ()
                cap_ready = False
                missing_caps = ()
            elif meta.has_structured_applicability and meta.metadata_valid:
                metadata_state = "structured"
                target_scope = meta.target.scope
                target_service = meta.target.service
                evaluation = evaluate_applicability(meta.applicability, value_map)
                predicate_result, missing_facts = _finalize_required_facts(
                    predicate_result=evaluation.result,
                    eval_missing=evaluation.missing_facts,
                    required_facts=meta.required_facts,
                    value_map=value_map,
                )
                matched = evaluation.matched_fact_keys
                cap_ready, missing_caps = _capability_readiness(
                    any_of=required_any,
                    all_of=required_all,
                    available=available_set,
                )
            else:
                metadata_state = "legacy"
                predicate_result = None
                target_scope = None
                target_service = ""
                matched = ()
                missing_facts = ()
                cap_ready = False
                missing_caps = ()

            candidates.append(
                FrameworkCandidate(
                    host_id=host_id,
                    framework_id=framework.id,
                    framework_version=version,
                    family_id=family_id,
                    language=language,
                    metadata_state=metadata_state,
                    predicate_result=predicate_result,
                    target_scope=target_scope,
                    target_service=target_service,
                    matched_fact_keys=matched,
                    missing_facts=missing_facts,
                    required_any_capabilities=required_any,
                    required_all_capabilities=required_all,
                    available_capabilities=available,
                    missing_capabilities=missing_caps,
                    capability_ready=cap_ready,
                    applicability_fingerprint=fingerprint,
                )
            )

    candidates.sort(
        key=lambda c: (
            c.host_id,
            c.family_id,
            c.language,
            c.framework_id,
            c.framework_version,
        )
    )
    return candidates

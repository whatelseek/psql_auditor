"""Framework candidate evaluation before/after discovery (INPUT-005)."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from auditor.domain.applicability import (
    FrameworkApplicabilityMeta,
    evaluate_applicability,
)
from auditor.domain.normalized_facts import HostFactSet
from auditor.frameworks import Framework
from auditor.inventory.framework_meta import list_frameworks_with_meta
from auditor.tool_registry import ToolRegistry, get_tool_registry


class FrameworkCandidate(BaseModel):
    """One host/framework pair after predicate evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host_id: StrictStr
    framework_id: StrictStr
    framework_version: StrictStr = ""
    predicate_result: StrictStr
    matched_predicates: tuple[StrictStr, ...] = ()
    missing_facts: tuple[StrictStr, ...] = ()
    required_capabilities: tuple[StrictStr, ...] = ()
    required_facts: tuple[StrictStr, ...] = ()
    available_capabilities: tuple[StrictStr, ...] = ()
    missing_capabilities: tuple[StrictStr, ...] = ()


def authorized_capability_ids(registry: ToolRegistry | None = None) -> set[str]:
    """Return capability strings exposed by authorized executable tools."""
    reg = registry or get_tool_registry()
    caps: set[str] = set()
    for tool in reg.authorized_tools():
        caps.update(tool.capabilities)
    return caps


def evaluate_framework_candidates(
    *,
    host_facts: dict[str, HostFactSet],
    agents_dir: Path | str | None = None,
    registry: ToolRegistry | None = None,
    include_invalid_frameworks: bool = False,
) -> list[FrameworkCandidate]:
    """Deterministically evaluate every valid framework against known facts."""
    reg = registry or get_tool_registry()
    available_caps = authorized_capability_ids(reg)
    pairs = list_frameworks_with_meta(agents_dir)
    candidates: list[FrameworkCandidate] = []

    for host_id in sorted(host_facts):
        facts = host_facts[host_id].as_map()
        for framework, meta in pairs:
            if not include_invalid_frameworks and (
                not framework.executable or not meta.metadata_valid
            ):
                continue
            # Prefer language-primary variants: skip _ru when en twin exists for same family
            # by evaluating all; callers may filter later. Evaluate all executable frameworks.
            candidate = evaluate_one_candidate(
                host_id=host_id,
                framework=framework,
                meta=meta,
                facts=facts,
                available_caps=available_caps,
            )
            candidates.append(candidate)

    # Stable ordering for determinism.
    candidates.sort(key=lambda c: (c.host_id, c.framework_id, c.framework_version))
    return candidates


def evaluate_one_candidate(
    *,
    host_id: str,
    framework: Framework,
    meta: FrameworkApplicabilityMeta,
    facts: dict[str, object],
    available_caps: set[str],
) -> FrameworkCandidate:
    """Evaluate one framework against one host fact map."""
    if not meta.metadata_valid:
        return FrameworkCandidate(
            host_id=host_id,
            framework_id=framework.id,
            framework_version=framework.version or "0",
            predicate_result="invalid",
            matched_predicates=(),
            missing_facts=(),
            required_capabilities=_required_caps(meta),
            required_facts=meta.required_facts,
            available_capabilities=tuple(sorted(available_caps)),
            missing_capabilities=_missing_caps(meta, available_caps),
        )

    result, matched, missing = evaluate_applicability(meta.applicability, facts)
    # required_facts that are absent also count as missing evidence
    for key in meta.required_facts:
        if key not in facts or facts.get(key) is None:
            if key not in missing:
                missing.append(key)
            if result == "matched":
                result = "missing_evidence"

    return FrameworkCandidate(
        host_id=host_id,
        framework_id=framework.id,
        framework_version=framework.version or "0",
        predicate_result=result,
        matched_predicates=tuple(matched),
        missing_facts=tuple(sorted(set(missing))),
        required_capabilities=_required_caps(meta),
        required_facts=meta.required_facts,
        available_capabilities=tuple(sorted(available_caps)),
        missing_capabilities=_missing_caps(meta, available_caps),
    )


def _required_caps(meta: FrameworkApplicabilityMeta) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys([*meta.required_capabilities.any_of, *meta.required_capabilities.all_of])
    )


def _missing_caps(meta: FrameworkApplicabilityMeta, available: set[str]) -> tuple[str, ...]:
    missing: list[str] = []
    for cap in meta.required_capabilities.all_of:
        if cap not in available:
            missing.append(cap)
    if meta.required_capabilities.any_of:
        if not any(cap in available for cap in meta.required_capabilities.any_of):
            missing.extend(meta.required_capabilities.any_of)
    return tuple(dict.fromkeys(missing))

"""Dynamic metadata-driven framework selection (INPUT-005).

Replaces hardcoded platform→framework maps with declarative Markdown
applicability predicates evaluated against the normalized fact namespace.
"""

from __future__ import annotations

from pathlib import Path

from auditor.domain.inventory import (
    ClientInventory,
    FrameworkSelectionDecision,
    TechnologyDetection,
)
from auditor.domain.normalized_facts import (
    HostFactSet,
    NormalizedFact,
    build_inventory_fact_sets,
)
from auditor.inventory.framework_candidates import (
    FrameworkCandidate,
    evaluate_framework_candidates,
)
from auditor.inventory.framework_meta import list_frameworks_with_meta


def select_frameworks_dynamic(
    inventory: ClientInventory,
    detections: list[TechnologyDetection],
    *,
    agents_dir: Path | str | None = None,
    host_facts: dict[str, HostFactSet] | None = None,
    extras: dict[str, list[NormalizedFact]] | None = None,
) -> list[FrameworkSelectionDecision]:
    """Select frameworks from Markdown applicability metadata (no hardcoded maps)."""
    facts = host_facts or build_inventory_fact_sets(inventory, detections, extras=extras)
    candidates = evaluate_framework_candidates(host_facts=facts, agents_dir=agents_dir)
    decisions = candidates_to_decisions(candidates, facts)
    conflicted_os = {c.host_id for c in inventory.conflicts if c.fact in {"os_family", "os_name"}}
    if conflicted_os:
        adjusted: list[FrameworkSelectionDecision] = []
        for decision in decisions:
            host_id = decision.target_id.split("/", 1)[0]
            if host_id in conflicted_os and decision.status == "selected":
                adjusted.append(
                    decision.model_copy(
                        update={
                            "status": "requires_operator_decision",
                            "reason": (
                                "OS evidence conflicts between inventory and discovery; "
                                "operator decision required before framework selection"
                            ),
                            "confidence": 0.0,
                        }
                    )
                )
            else:
                adjusted.append(decision)
        decisions = adjusted
    # Prefer one language variant per family (en over ru when both match).
    decisions = _dedupe_language_variants(decisions, agents_dir=agents_dir)
    decisions.sort(key=lambda d: (d.target_id, d.framework_id, d.status))
    return decisions


def candidates_to_decisions(
    candidates: list[FrameworkCandidate],
    host_facts: dict[str, HostFactSet],
) -> list[FrameworkSelectionDecision]:
    """Map candidate predicate results to FrameworkSelectionDecision statuses."""
    decisions: list[FrameworkSelectionDecision] = []
    for cand in candidates:
        # Skip always-on IT duplicates later; emit decisions for all hosts.
        status, reason = _decision_for_candidate(cand, host_facts.get(cand.host_id))
        if status is None:
            continue
        target_id = _target_id_for(cand, host_facts.get(cand.host_id))
        decisions.append(
            FrameworkSelectionDecision(
                framework_id=cand.framework_id,
                framework_version=cand.framework_version,
                target_id=target_id,
                reason=reason,
                status=status,
                missing_capabilities=cand.missing_capabilities,
                matched_facts=cand.matched_predicates,
                missing_facts=cand.missing_facts,
                evidence_refs=_evidence_refs(host_facts.get(cand.host_id), cand),
                confidence=_confidence(cand, host_facts.get(cand.host_id)),
            )
        )
    return decisions


def _decision_for_candidate(
    cand: FrameworkCandidate,
    fact_set: HostFactSet | None,
) -> tuple[str | None, str]:
    if cand.predicate_result == "invalid":
        return (
            "blocked",
            f"Framework {cand.framework_id} has invalid applicability metadata",
        )
    if cand.predicate_result == "not_matched":
        # Do not clutter the plan with frameworks that clearly do not apply.
        return None, ""
    if cand.missing_capabilities:
        return (
            "blocked",
            "No authorized executable tool is available for required capability "
            f"{cand.missing_capabilities[0]}",
        )
    if cand.predicate_result == "missing_evidence":
        return (
            "requires_operator_decision",
            "Missing evidence for required facts: "
            + ", ".join(cand.missing_facts[:6] or ["(unspecified)"]),
        )
    # matched
    if _matched_only_suspected(cand, fact_set):
        return (
            "requires_operator_decision",
            f"{cand.framework_id} matched on suspected evidence only; "
            "operator confirmation required",
        )
    return (
        "selected",
        f"{cand.framework_id} selected from declarative applicability metadata "
        f"({len(cand.matched_predicates)} matched predicate(s))",
    )


def _matched_only_suspected(
    cand: FrameworkCandidate,
    fact_set: HostFactSet | None,
) -> bool:
    if fact_set is None:
        return False
    fmap = fact_set.as_map()
    suspected = False
    confirmed = False
    for key, value in fmap.items():
        if not key.startswith("technology.") or not key.endswith(".status"):
            continue
        # Only consider technologies referenced by this framework's matched preds
        tech = key.removeprefix("technology.").removesuffix(".status")
        related = any(tech in m for m in cand.matched_predicates) or any(
            tech in f for f in cand.required_facts
        )
        if not related and cand.framework_id not in {
            "postgres_cis",
            "postgres_cis_ru",
            "postgresql_health",
            "redis_health",
        }:
            continue
        if cand.framework_id.startswith("postgres") and tech != "postgresql":
            continue
        if cand.framework_id.startswith("redis") and tech != "redis":
            continue
        if value == "suspected":
            suspected = True
        if value == "confirmed":
            confirmed = True
    return suspected and not confirmed


def _target_id_for(cand: FrameworkCandidate, fact_set: HostFactSet | None) -> str:
    fw = cand.framework_id.lower()
    if "postgres" in fw or "postgresql" in fw:
        return f"{cand.host_id}/postgresql"
    if "redis" in fw:
        return f"{cand.host_id}/redis"
    if _is_broad_always_framework(cand.framework_id):
        # Client-level infra frameworks stay client-scoped when domain IT always-on.
        # Per-host expansion happens in generate_audit_plan.
        return cand.host_id
    return cand.host_id


def _is_broad_always_framework(framework_id: str) -> bool:
    return framework_id in {"host_facts", "host_facts_ru", "it_audit"}


def _evidence_refs(
    fact_set: HostFactSet | None,
    cand: FrameworkCandidate,
) -> tuple[str, ...]:
    if fact_set is None:
        return ()
    refs: list[str] = []
    for fact in fact_set.facts:
        if fact.evidence_ref and (
            any(fact.fact in m for m in cand.matched_predicates)
            or fact.fact in cand.required_facts
            or fact.fact.startswith("technology.")
        ):
            refs.append(fact.evidence_ref)
    return tuple(dict.fromkeys(refs))[:12]


def _confidence(cand: FrameworkCandidate, fact_set: HostFactSet | None) -> float:
    if cand.predicate_result != "matched":
        return 0.0
    if _matched_only_suspected(cand, fact_set):
        return 0.4
    return 1.0


def _dedupe_language_variants(
    decisions: list[FrameworkSelectionDecision],
    *,
    agents_dir: Path | str | None,
) -> list[FrameworkSelectionDecision]:
    """Keep a single language variant per family+target+status group (prefer en)."""
    family_of = {
        fw.id: (fw.family_id or fw.id, fw.language)
        for fw, _meta in list_frameworks_with_meta(agents_dir)
    }
    # Group selected/blocked/etc by (target, family, status)
    best: dict[tuple[str, str, str], FrameworkSelectionDecision] = {}
    order_score = {"en": 0, "any": 1, "ru": 2}

    for decision in decisions:
        family, lang = family_of.get(decision.framework_id, (decision.framework_id, "any"))
        key = (decision.target_id, family, decision.status)
        current = best.get(key)
        if current is None:
            best[key] = decision
            continue
        cur_lang = family_of.get(current.framework_id, (family, "any"))[1]
        if order_score.get(lang, 9) < order_score.get(cur_lang, 9):
            best[key] = decision
    return list(best.values())


# --- Legacy path (explicit opt-in only) --------------------------------------


def select_frameworks_legacy_tech_mapping(
    inventory: ClientInventory,
    detections: list[TechnologyDetection],
    *,
    agents_dir: Path | str | None = None,
) -> list[FrameworkSelectionDecision]:
    """Deprecated hardcoded platform map — kept behind explicit legacy flag."""
    from auditor.inventory import select_frameworks as legacy

    return legacy._legacy_select_frameworks_for_inventory(  # noqa: SLF001
        inventory, detections, agents_dir=agents_dir
    )

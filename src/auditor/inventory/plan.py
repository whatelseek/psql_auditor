"""Generate and confirm inventory-driven audit plans."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from auditor.domain.audit_plan import (
    AuditPlan,
    AuditPlanSummary,
    AuditPlanTarget,
    PlanConfirmationRejected,
    PlanConfirmationRequest,
)
from auditor.domain.inventory import ClientInventory, TechnologyDetection
from auditor.inventory.select_frameworks import select_frameworks_for_inventory


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _plan_id(client_id: str, inventory_version_id: str) -> str:
    digest = hashlib.sha256(f"{client_id}:{inventory_version_id}".encode()).hexdigest()[:12]
    return f"plan-{digest}"


def generate_audit_plan(
    inventory: ClientInventory,
    detections: list[TechnologyDetection],
    *,
    agents_dir: Path | str | None = None,
) -> AuditPlan:
    """Build a draft audit plan from inventory + technology detections.

    Plan generation is idempotent for the same inventory version: the plan id
    is derived from ``client_id`` + ``inventory_version_id``.
    """
    decisions = select_frameworks_for_inventory(inventory, detections, agents_dir=agents_dir)
    host_by_id = {h.host_id: h for h in inventory.hosts}

    targets: list[AuditPlanTarget] = []
    for decision in decisions:
        if decision.status != "selected":
            continue
        if decision.target_id.startswith("client:"):
            # Client-level infrastructure — attach to first valid host as scope
            # marker is retained via target_id for reporting; skip host-less
            # execution rows when no hosts exist.
            if not inventory.hosts_without_errors():
                continue
            # Represent general assessment once against the client namespace.
            targets.append(
                AuditPlanTarget(
                    target_id=decision.target_id,
                    host_id=inventory.client_id,
                    service="infrastructure",
                    framework_id=decision.framework_id,
                    framework_version=decision.framework_version,
                    connection_methods=(),
                    expected_evidence_sources=("inventory", "questionnaire"),
                    limitations=(),
                )
            )
            continue

        host_id = decision.target_id.split("/", 1)[0]
        host = host_by_id.get(host_id)
        if host is None:
            continue
        service = ""
        if "/" in decision.target_id:
            service = decision.target_id.split("/", 1)[1]
        limitations: list[str] = []
        if not host.address:
            limitations.append("missing host address")
        if not host.connection_types:
            limitations.append("no connection method declared")
        evidence_sources: list[str] = ["inventory"]
        if "ssh" in host.connection_types:
            evidence_sources.insert(0, "ssh")
        if "winrm" in host.connection_types:
            evidence_sources.insert(0, "winrm")
        if service == "postgresql" or "postgresql" in host.connection_types:
            evidence_sources.append("postgresql")
        targets.append(
            AuditPlanTarget(
                target_id=decision.target_id,
                host_id=host_id,
                service=service,
                framework_id=decision.framework_id,
                framework_version=decision.framework_version,
                connection_methods=tuple(host.connection_types),
                expected_evidence_sources=tuple(dict.fromkeys(evidence_sources)),
                limitations=tuple(limitations),
            )
        )

    linux_hosts = sum(1 for h in inventory.hosts if h.os_family == "linux")
    windows_hosts = sum(1 for h in inventory.hosts if h.os_family == "windows")
    pg_instances = sum(
        1 for h in inventory.hosts if any(s.name == "postgresql" for s in h.services)
    )
    selected_counts: dict[str, int] = {}
    for t in targets:
        selected_counts[t.framework_id] = selected_counts.get(t.framework_id, 0) + 1

    missing: list[str] = []
    for issue in inventory.issues:
        if issue.level in {"error", "warning"} or issue.code == "needs_discovery":
            missing.append(f"{issue.code}: {issue.message}")
    unresolved = [
        "Confirm read-only access for all selected targets",
        *(f"Questionnaire pending: {name}" for name in inventory.questionnaires),
        *(
            f"Clarify conflict on {c.host_id}.{c.fact}: "
            f"inventory={c.inventory_value!r} vs discovered={c.discovered_value!r}"
            for c in inventory.conflicts
        ),
        *(
            f"Clarify framework selection for {d.target_id}: {d.reason}"
            for d in decisions
            if d.status == "considered"
        ),
    ]

    # Coverage heuristic: hosts without errors / total hosts, adjusted for missing data.
    total = len(inventory.hosts) or 1
    healthy = len(inventory.hosts_without_errors())
    coverage = healthy / total
    if inventory.error_count:
        coverage *= 0.85

    summary = AuditPlanSummary(
        total_hosts=len(inventory.hosts),
        linux_hosts=linux_hosts,
        windows_hosts=windows_hosts,
        postgresql_instances=pg_instances,
        total_audit_target_instances=len(targets),
        selected_framework_counts=selected_counts,
        estimated_coverage=round(coverage, 3),
        potentially_destructive=False,
    )

    return AuditPlan(
        plan_id=_plan_id(inventory.client_id, inventory.version.version_id),
        client_id=inventory.client_id,
        inventory_version_id=inventory.version.version_id,
        inventory_content_hash=inventory.version.content_hash,
        status="draft",
        targets=tuple(targets),
        framework_decisions=tuple(decisions),
        technology_detections=tuple(detections),
        unresolved_questions=tuple(unresolved),
        missing_data=tuple(missing),
        validation_issues=inventory.issues,
        summary=summary,
        created_at=_utc_now(),
    )


def confirm_audit_plan(
    plan: AuditPlan,
    request: PlanConfirmationRequest,
) -> AuditPlan:
    """Apply an operator confirmation action to a draft plan."""
    if plan.status not in {"draft", "confirmed"}:
        raise PlanConfirmationRejected(
            f"plan {plan.plan_id} is {plan.status} and cannot be modified",
            code="plan_not_modifiable",
        )

    if request.action == "reject":
        return plan.model_copy(
            update={
                "status": "rejected",
                "confirmation_note": request.note,
                "confirmed_at": None,
            }
        )

    if request.action == "reanalyze":
        return plan.model_copy(
            update={
                "status": "superseded",
                "confirmation_note": request.note or "reanalyze requested",
            }
        )

    targets = list(plan.targets)
    if request.action == "exclude_host":
        wanted = {h.lower() for h in request.host_ids}
        targets = [
            t.model_copy(update={"excluded": True})
            if t.host_id.lower() in wanted or t.target_id.lower() in wanted
            else t
            for t in targets
        ]
    elif request.action == "exclude_framework":
        wanted = {f.lower() for f in request.framework_ids}
        targets = [
            t.model_copy(update={"excluded": True}) if t.framework_id.lower() in wanted else t
            for t in targets
        ]
    elif request.action == "add_framework":
        # Additive frameworks are recorded as non-excluded placeholders on hosts.
        for host_id in request.host_ids or sorted({t.host_id for t in targets}):
            for fw_id in request.framework_ids:
                targets.append(
                    AuditPlanTarget(
                        target_id=host_id,
                        host_id=host_id,
                        service="",
                        framework_id=fw_id,
                        framework_version="",
                        connection_methods=(),
                        expected_evidence_sources=("inventory",),
                        limitations=("operator-added framework",),
                        excluded=False,
                    )
                )
    elif request.action in {
        "correct_inventory",
        "provide_evidence",
        "mark_exception",
    }:
        return plan.model_copy(
            update={
                "status": "draft",
                "confirmation_note": request.note or request.action,
            }
        )
    elif request.action != "approve":
        raise PlanConfirmationRejected(
            f"unsupported plan action {request.action!r}",
            code="unsupported_plan_action",
        )

    active = [t for t in targets if not t.excluded]
    if request.action == "approve" and not active:
        raise PlanConfirmationRejected(
            "cannot confirm an empty audit plan",
            code="empty_plan",
        )

    status = "confirmed" if request.action == "approve" else "draft"
    counts: dict[str, int] = {}
    for t in active:
        counts[t.framework_id] = counts.get(t.framework_id, 0) + 1
    summary = plan.summary.model_copy(
        update={
            "total_audit_target_instances": len(active),
            "selected_framework_counts": counts,
        }
    )
    return plan.model_copy(
        update={
            "status": status,
            "targets": tuple(targets),
            "summary": summary,
            "confirmed_at": _utc_now() if status == "confirmed" else None,
            "confirmation_note": request.note,
        }
    )


def ensure_plan_confirmed(plan: AuditPlan) -> AuditPlan:
    """Reject audit launch when the plan is not confirmed."""
    if not plan.is_executable():
        raise PlanConfirmationRejected(
            "audit launch rejected: plan is not confirmed "
            f"(status={plan.status}, active_targets={len(plan.active_targets)})",
            code="plan_not_confirmed",
        )
    return plan


def assert_plan_matches_inventory(plan: AuditPlan, inventory: ClientInventory) -> None:
    """Reject confirmation/start when inventory changed since plan generation."""
    if (
        plan.inventory_version_id != inventory.version.version_id
        or plan.inventory_content_hash != inventory.version.content_hash
    ):
        raise PlanConfirmationRejected(
            "audit plan is stale: inventory changed since plan generation; "
            "re-run inventory analyze / audit plan to regenerate",
            code="plan_stale",
        )


def plan_confirmation_prompt(plan: AuditPlan) -> str:
    """Render the operator confirmation question for the plan."""
    s = plan.summary
    infra_count = s.selected_framework_counts.get(
        "host_facts",
        s.selected_framework_counts.get("it_audit", 0),
    )
    lines = [
        f"The system detected {s.total_hosts} hosts and selected the following audits:",
        f"- {s.linux_hosts} Ubuntu/Linux host audits",
        f"- {s.windows_hosts} Windows Server audit(s)",
        f"- {s.postgresql_instances} PostgreSQL audit(s)",
        f"- {infra_count} general infrastructure assessment(s)",
        "",
        f"Total audit target instances: {s.total_audit_target_instances}",
        f"Estimated coverage: {s.estimated_coverage:.0%}",
        "Potentially destructive actions: none (read-only mode)",
        "",
        "Do you confirm the audit launch?",
    ]
    if plan.missing_data:
        lines[1:1] = ["", "Missing / limited data:", *[f"- {m}" for m in plan.missing_data[:8]], ""]
    return "\n".join(lines)


def persist_plan(plan: AuditPlan, path: Path) -> Path:
    """Write a plan JSON snapshot (secret-free)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(plan.model_dump(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def load_plan(path: Path) -> AuditPlan:
    """Load a previously persisted audit plan."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return AuditPlan.model_validate(data)

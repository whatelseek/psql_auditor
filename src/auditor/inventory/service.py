"""High-level inventory analyze → plan → confirm → execute AuditRequest."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from auditor.client_registry import get_client_registry
from auditor.config import Settings, load_settings
from auditor.domain.audit_plan import (
    AuditPlan,
    PlanConfirmationRejected,
    PlanConfirmationRequest,
)
from auditor.domain.audit_request import (
    AUDIT_REQUEST_SCHEMA_VERSION,
    POC_TOOL_PROFILE,
    parse_audit_request,
    validate_audit_request_semantics,
)
from auditor.domain.inventory import ClientInventory
from auditor.inventory.client_name import validate_client_name
from auditor.inventory.detect import detect_technologies
from auditor.inventory.discovery import (
    DiscoveryCollector,
    NoopDiscoveryCollector,
    default_discovery_collector,
    reconcile_inventory,
)
from auditor.inventory.discovery_evidence import COLLECTOR_VERSION
from auditor.inventory.loaders import InventoryLoadError, load_raw_inventory
from auditor.inventory.normalize import normalize_inventory
from auditor.inventory.plan import (
    assert_plan_matches_framework_hash,
    assert_plan_matches_inventory,
    assert_plan_matches_preflight,
    assert_plan_matches_tool_registry,
    ensure_plan_confirmed,
    load_plan,
    persist_plan,
    plan_confirmation_prompt,
)
from auditor.inventory.plan import (
    confirm_audit_plan as apply_plan_confirmation,
)
from auditor.inventory.plan import (
    generate_audit_plan as build_plan,
)
from auditor.inventory.preflight import (
    build_preflight_revision,
    load_latest_preflight,
    persist_preflight_revision,
)

AuditExecutor = Callable[[Any], Awaitable[dict[str, Any]]]

EFFECTIVE_INVENTORY_FILENAME = "effective.inventory.json"


def load_client_inventory(
    inventory_dir: Path | str,
    client_name: str,
) -> ClientInventory:
    """Load and normalize a client inventory (Markdown / YAML / JSON)."""
    client = validate_client_name(client_name)
    raw, path, fmt = load_raw_inventory(inventory_dir, client)
    return normalize_inventory(
        raw,
        client_name=client,
        source_path=path,
        source_format=fmt,
    )


def plans_dir_for(inventory_dir: Path | str, client_name: str) -> Path:
    """Return ``{inventory_dir}/{client}/.audit_plans``."""
    client = validate_client_name(client_name)
    return Path(inventory_dir) / client / ".audit_plans"


def persist_effective_inventory(
    inventory: ClientInventory,
    persist_dir: Path | str,
) -> Path:
    """Persist the reconciled/effective inventory used for plan validation."""
    root = Path(persist_dir)
    root.mkdir(parents=True, exist_ok=True)
    payload = _safe_inventory_dump(inventory)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path = root / EFFECTIVE_INVENTORY_FILENAME
    path.write_text(text, encoding="utf-8")
    (root / f"{inventory.version.version_id}.inventory.json").write_text(text, encoding="utf-8")
    return path


def load_effective_inventory(
    inventory_dir: Path | str,
    client_name: str,
) -> ClientInventory | None:
    """Load persisted effective inventory from the client's audit-plans dir."""
    path = plans_dir_for(inventory_dir, client_name) / EFFECTIVE_INVENTORY_FILENAME
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return ClientInventory.model_validate(data)


def resolve_effective_inventory(
    inventory_dir: Path | str,
    client_name: str,
    *,
    inventory: ClientInventory | None = None,
) -> ClientInventory:
    """Prefer persisted effective inventory; fall back to source or provided."""
    if inventory is not None:
        return inventory
    effective = load_effective_inventory(inventory_dir, client_name)
    if effective is not None:
        return effective
    return load_client_inventory(inventory_dir, client_name)


def validate_client_inventory(
    inventory_dir: Path | str,
    client_name: str,
) -> ClientInventory:
    """Load inventory and return it with validation issues attached."""
    return load_client_inventory(inventory_dir, client_name)


def analyze_client_inventory(
    inventory_dir: Path | str,
    client_name: str,
    *,
    agents_dir: Path | str | None = None,
    persist_dir: Path | str | None = None,
    discoverer: DiscoveryCollector | None = None,
    discovery: bool = True,
    artifacts_root: Path | str | None = None,
) -> tuple[ClientInventory, AuditPlan]:
    """Validate inventory, run discovery (default on), and generate a draft plan.

    Production discovery uses :class:`CompositeDiscoveryCollector` unless
    ``discovery=False`` (no-op) or an explicit ``discoverer`` is injected.
    """
    inventory_dir = Path(inventory_dir)
    client_name = validate_client_name(client_name)
    inventory = load_client_inventory(inventory_dir, client_name)

    # Do not start discovery when inventory validation contains errors.
    discovery_blocked = inventory.error_count > 0
    if discovery_blocked:
        collector: DiscoveryCollector = NoopDiscoveryCollector()
        discoveries: list[Any] = []
    elif discoverer is not None:
        collector = discoverer
        discoveries = collector.discover(inventory)
    else:
        if artifacts_root is None and discovery:
            try:
                artifacts_root = load_settings().evidence_dir
            except Exception:  # noqa: BLE001
                artifacts_root = Path("artifacts")
        collector = default_discovery_collector(
            inventory_dir,
            client_name,
            artifacts_root=artifacts_root,
            enabled=discovery,
        )
        discoveries = collector.discover(inventory)
    if discoveries:
        inventory = reconcile_inventory(inventory, discoveries)

    detections = detect_technologies(inventory)
    if artifacts_root is not None:
        try:
            from auditor.inventory.tool_discovery import (
                sync_capability_snapshots_from_detections,
            )

            sync_capability_snapshots_from_detections(
                inventory,
                detections,
                artifacts_root=artifacts_root,
            )
        except Exception:  # noqa: BLE001
            pass

    # Dynamic selection path: normalized facts → candidates → registry discovery
    # → re-evaluate. SSH collector facts already feed detections; registry tools
    # fill remaining gaps (TCP/HTTP/SNMP) without hardcoded framework maps.
    try:
        from auditor.domain.normalized_facts import (
            build_inventory_fact_sets,
            facts_to_serializable,
            merge_facts,
        )
        from auditor.inventory.discovery_plan import build_discovery_plan
        from auditor.inventory.framework_candidates import evaluate_framework_candidates
        from auditor.inventory.registry_discovery import (
            execute_discovery_plan_sync,
            persist_discovery_artifacts,
        )

        fact_sets = build_inventory_fact_sets(inventory, detections)
        candidates = evaluate_framework_candidates(host_facts=fact_sets, agents_dir=agents_dir)
        dplan = build_discovery_plan(candidates, fact_sets, agents_dir=agents_dir)
        # Skip steps whose expected facts are already present (e.g. after SSH).
        # SSH evidence is collected by SshDiscoveryCollector; this executor only
        # runs TCP/HTTP/SNMP registered adapters.
        pending = []
        for step in dplan.steps:
            if step.capability not in {
                "tcp.connect",
                "http.get",
                "snmp.get",
                "snmp.walk",
            }:
                continue
            fmap = fact_sets.get(step.host_id)
            have = fmap.as_map() if fmap is not None else {}
            if step.expected_facts and all(f in have for f in step.expected_facts):
                continue
            pending.append(step)
        from auditor.inventory.discovery_plan import DiscoveryPlan as _DPlan

        pending_plan = _DPlan(plan_id=dplan.plan_id, steps=tuple(pending))
        invocations: list[Any] = []
        if pending_plan.steps and discovery and not discovery_blocked:
            host_addresses = {h.host_id: (h.address or h.host_id) for h in inventory.hosts}
            try:
                pending_plan, extras, invocations = execute_discovery_plan_sync(
                    pending_plan, host_addresses=host_addresses
                )
                for host_id, extra in extras.items():
                    if host_id in fact_sets:
                        fact_sets[host_id] = merge_facts(fact_sets[host_id], extra)
                candidates = evaluate_framework_candidates(
                    host_facts=fact_sets, agents_dir=agents_dir
                )
            except Exception:  # noqa: BLE001
                pass
        if artifacts_root is not None:
            try:
                persist_discovery_artifacts(
                    artifacts_root=artifacts_root,
                    client_slug=client_name,
                    inventory_version_id=inventory.version.version_id,
                    candidates=candidates,
                    discovery_plan=pending_plan,
                    fact_sets={k: list(v.facts) for k, v in fact_sets.items()},
                    invocations=invocations,
                )
                _ = facts_to_serializable(fact_sets)
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass

    # Build provisional plan decisions for selected framework list / revision.
    provisional = build_plan(inventory, detections, agents_dir=agents_dir)
    selected = sorted(
        {d.framework_id for d in provisional.framework_decisions if d.status == "selected"}
    )
    revision = build_preflight_revision(
        inventory,
        discoveries=discoveries,
        selected_frameworks=selected,
        collector_versions={
            "composite": COLLECTOR_VERSION,
            "ssh": COLLECTOR_VERSION,
            "winrm": COLLECTOR_VERSION,
            "noop": "0" if isinstance(collector, NoopDiscoveryCollector) else COLLECTOR_VERSION,
        },
    )
    if artifacts_root is not None:
        try:
            persist_preflight_revision(
                revision,
                artifacts_root=artifacts_root,
                client_slug=client_name,
            )
        except Exception:  # noqa: BLE001
            pass

    plan = build_plan(
        inventory,
        detections,
        agents_dir=agents_dir,
        discovery_result_hash=revision.discovery_result_hash,
        effective_facts_hash=revision.effective_facts_hash,
        preflight_revision_id=revision.revision_id,
    )
    # Always persist effective inventory next to plans when possible so
    # confirm/start validate against discovery-reconciled facts.
    plans_root = (
        Path(persist_dir) if persist_dir is not None else plans_dir_for(inventory_dir, client_name)
    )
    persist_effective_inventory(inventory, plans_root)
    if persist_dir is not None:
        persist_plan(plan, plans_root / f"{plan.plan_id}.json")
    return inventory, plan


def generate_audit_plan(
    inventory_dir: Path | str,
    client_name: str,
    *,
    agents_dir: Path | str | None = None,
    discoverer: DiscoveryCollector | None = None,
    discovery: bool = True,
    artifacts_root: Path | str | None = None,
) -> AuditPlan:
    """Convenience wrapper returning only the draft plan."""
    _inventory, plan = analyze_client_inventory(
        inventory_dir,
        client_name,
        agents_dir=agents_dir,
        discoverer=discoverer,
        discovery=discovery,
        artifacts_root=artifacts_root,
    )
    return plan


def confirm_audit_plan(
    plan: AuditPlan,
    *,
    action: str = "approve",
    host_ids: list[str] | None = None,
    framework_ids: list[str] | None = None,
    note: str = "",
    inventory_dir: Path | str | None = None,
    client_name: str | None = None,
    inventory: ClientInventory | None = None,
) -> AuditPlan:
    """Confirm, reject, or adjust a draft plan.

    When ``action`` is ``approve``, reloads the effective (discovery-reconciled)
    inventory when available and rejects with ``audit_plan_stale`` if the
    inventory hash/version or framework selection diverged.
    """
    if action == "approve":
        if inventory_dir is not None and client_name is not None:
            source = load_client_inventory(inventory_dir, client_name)
            assert_plan_matches_inventory(plan, source)

        current = inventory
        if current is None:
            if inventory_dir is None or client_name is None:
                raise PlanConfirmationRejected(
                    "inventory_dir and client_name are required to confirm a plan",
                    code="missing_inventory_context",
                )
            current = resolve_effective_inventory(inventory_dir, client_name)
        assert_plan_matches_inventory(plan, current)
        assert_plan_matches_tool_registry(plan)
        from auditor.inventory.plan import framework_selection_hash
        from auditor.inventory.select_frameworks import select_frameworks_for_inventory

        current_fw_hash = framework_selection_hash(
            select_frameworks_for_inventory(
                current,
                detect_technologies(current),
                agents_dir=None,
            )
        )
        assert_plan_matches_framework_hash(plan, framework_hash=current_fw_hash)
        # If a newer preflight exists for the same inventory with different
        # effective facts, the plan is stale (discovery changed post-plan).
        if inventory_dir is not None and client_name is not None:
            try:
                settings = load_settings()
                latest = load_latest_preflight(settings.evidence_dir, client_name)
            except Exception:  # noqa: BLE001
                latest = None
            if latest is not None and latest.inventory_version_id == plan.inventory_version_id:
                assert_plan_matches_preflight(
                    plan,
                    discovery_result_hash=latest.discovery_result_hash,
                    effective_facts_hash=latest.effective_facts_hash,
                )

    request = PlanConfirmationRequest(
        action=action,  # type: ignore[arg-type]
        host_ids=tuple(host_ids or ()),
        framework_ids=tuple(framework_ids or ()),
        note=note,
    )
    return apply_plan_confirmation(plan, request)


def reject_audit_launch(plan: AuditPlan) -> None:
    """Raise if an unconfirmed plan is used to start an audit."""
    ensure_plan_confirmed(plan)


def plan_to_audit_request_payload(
    plan: AuditPlan,
    *,
    inventory: ClientInventory,
    client_id: str,
    client_slug: str,
    report_language: str = "en",
    hitl_enabled: bool = True,
    archive_enabled: bool = True,
    max_parallel_assessments: int = 5,
    max_parallel_host_jobs: int = 2,
) -> dict[str, Any]:
    """Convert a confirmed plan into an INPUT-001 AuditRequest payload.

    ``client_id`` must be the registry id. Target refs use host addresses so
    ``list_client_ssh_targets`` can resolve them. Confirmed plan targets are
    used as-is so plan identity matches execution identity (client-level
    frameworks must already be expanded to explicit per-host targets, or
    appear as a single client-level job).
    """
    ensure_plan_confirmed(plan)
    assert_plan_matches_inventory(plan, inventory)
    assert_plan_matches_tool_registry(plan)
    from auditor.inventory.plan import framework_selection_hash
    from auditor.inventory.select_frameworks import select_frameworks_for_inventory

    assert_plan_matches_framework_hash(
        plan,
        framework_hash=framework_selection_hash(
            select_frameworks_for_inventory(
                inventory,
                detect_technologies(inventory),
                agents_dir=None,
            )
        ),
    )

    host_by_id = {h.host_id: h for h in inventory.hosts}
    by_ref: dict[str, list[dict[str, str]]] = {}
    client_level: list[dict[str, str]] = []

    for target in plan.active_targets:
        pair = {
            "framework_id": target.framework_id,
            "framework_version": target.framework_version or "0",
        }
        if target.target_id.startswith("client:"):
            # Preserve as a single client-level job (not silent per-host fan-out).
            if pair not in client_level:
                client_level.append(pair)
            continue
        host = host_by_id.get(target.host_id)
        if host is None:
            continue
        ref = (host.address or host.host_id).strip()
        by_ref.setdefault(ref, [])
        if pair not in by_ref[ref]:
            by_ref[ref].append(pair)

    if client_level and not by_ref:
        # Explicit client-level-only plan: one synthetic target for the client.
        by_ref[f"client:{plan.client_id}"] = client_level
    elif client_level and by_ref:
        raise PlanConfirmationRejected(
            "confirmed plan mixes client-level targets with host targets; "
            "expand client frameworks to per-host targets before confirmation "
            "or keep a single client-level job",
            code="plan_identity_mismatch",
        )

    if not by_ref:
        raise PlanConfirmationRejected(
            "confirmed plan has no executable targets",
            code="empty_plan",
        )

    # Prefer on-disk directory casing (e.g. Testcompany) over lowercased slug.
    source = Path(inventory.version.source_path) if inventory.version.source_path else None
    dir_name = source.parent.name if source is not None and source.parent.name else client_slug
    inventory_ref = f"{dir_name}/INVENTORY.md"
    return {
        "schema_version": AUDIT_REQUEST_SCHEMA_VERSION,
        "client_id": client_id,
        "inventory": {
            "kind": "client_file",
            "ref": inventory_ref,
            "version_id": inventory.version.version_id,
            "content_hash": inventory.version.content_hash,
        },
        "targets": [
            {"inventory_target_ref": ref, "frameworks": frameworks}
            for ref, frameworks in by_ref.items()
        ],
        "tool_profile": POC_TOOL_PROFILE,
        "run_settings": {
            "report_language": report_language,
            "hitl_enabled": hitl_enabled,
            "archive_enabled": archive_enabled,
            "max_parallel_assessments": max_parallel_assessments,
            "max_parallel_host_jobs": max_parallel_host_jobs,
        },
    }


async def astart_confirmed_audit(
    inventory_dir: Path | str,
    client_name: str,
    plan: AuditPlan,
    *,
    settings: Settings | None = None,
    agents_dir: Path | str | None = None,
    note: str = "",
    executor: AuditExecutor | None = None,
    discoverer: DiscoveryCollector | None = None,
    refresh_discovery: bool = False,
) -> dict[str, Any]:
    """Confirm a fresh plan and execute it via ``arun_request`` (or ``executor``).

    Discovery is **not** re-run unless ``refresh_discovery=True`` or an explicit
    ``discoverer`` is provided for a refresh check. Async entry point for FastAPI.
    """
    settings = settings or load_settings()
    inventory_dir = Path(inventory_dir)
    client_name = validate_client_name(client_name)

    # Source inventory identity check + effective inventory for plan validation.
    source = load_client_inventory(inventory_dir, client_name)
    assert_plan_matches_inventory(plan, source)
    inventory = resolve_effective_inventory(inventory_dir, client_name)
    assert_plan_matches_inventory(plan, inventory)
    assert_plan_matches_tool_registry(plan)

    registry = get_client_registry(settings.evidence_dir)
    client = registry.ensure_client(display_name=client_name, slug=client_name)

    if refresh_discovery or discoverer is not None:
        # Explicit refresh only — compare against the confirmed plan hashes.
        inventory, refreshed_plan = analyze_client_inventory(
            inventory_dir,
            client_name,
            agents_dir=agents_dir or settings.agents_dir,
            discoverer=discoverer,
            discovery=True,
            artifacts_root=settings.evidence_dir,
            persist_dir=plans_dir_for(inventory_dir, client_name),
        )
        assert_plan_matches_preflight(
            plan,
            discovery_result_hash=refreshed_plan.discovery_result_hash,
            effective_facts_hash=refreshed_plan.effective_facts_hash,
        )
    else:
        # Stale check against latest stored preflight without re-running discovery.
        latest = load_latest_preflight(settings.evidence_dir, client_name)
        if latest is not None and latest.inventory_version_id == plan.inventory_version_id:
            assert_plan_matches_preflight(
                plan,
                discovery_result_hash=latest.discovery_result_hash,
                effective_facts_hash=latest.effective_facts_hash,
            )

    if plan.status != "confirmed":
        plan = confirm_audit_plan(
            plan,
            action="approve",
            note=note or "confirmed",
            inventory=inventory,
            inventory_dir=inventory_dir,
            client_name=client_name,
        )
    else:
        assert_plan_matches_inventory(plan, inventory)
        assert_plan_matches_tool_registry(plan)

    payload = plan_to_audit_request_payload(
        plan,
        inventory=inventory,
        client_id=client.client_id,
        client_slug=client.slug,
        report_language="en",
        hitl_enabled=bool(settings.hitl_enabled),
        archive_enabled=bool(settings.archive_enabled),
        max_parallel_assessments=int(settings.max_parallel_assessments),
        max_parallel_host_jobs=int(settings.max_parallel_host_jobs),
    )
    request = validate_audit_request_semantics(parse_audit_request(payload), settings)

    async def _default_execute(req: Any) -> dict[str, Any]:
        from auditor.graph import AuditorGraph

        graph = AuditorGraph(settings=settings)
        return await graph.arun_request(req, operator_context="CLI inventory-driven start")

    run_executor = executor or _default_execute
    result = await run_executor(request)
    return {
        "status": "started",
        "plan_id": plan.plan_id,
        "plan": plan,
        "client_id": client.client_id,
        "audit_run_id": result.get("audit_run_id") or "",
        "evidence_run_id": result.get("evidence_run_id") or "",
        "audit_run_status": result.get("audit_run_status") or "",
        "awaiting_hitl": bool(result.get("awaiting_hitl")),
        "audit_request": payload,
        "result": {
            k: result.get(k)
            for k in (
                "audit_run_id",
                "evidence_run_id",
                "audit_run_status",
                "thread_id",
                "awaiting_hitl",
                "archive_path",
                "archive_url",
            )
            if k in result
        },
    }


def start_confirmed_audit(
    inventory_dir: Path | str,
    client_name: str,
    plan: AuditPlan,
    *,
    settings: Settings | None = None,
    agents_dir: Path | str | None = None,
    note: str = "",
    executor: AuditExecutor | None = None,
    discoverer: DiscoveryCollector | None = None,
    refresh_discovery: bool = False,
) -> dict[str, Any]:
    """CLI-only synchronous wrapper around :func:`astart_confirmed_audit`.

    Uses ``asyncio.run`` and must not be called from an active event loop
    (FastAPI must ``await astart_confirmed_audit`` instead).
    """
    return asyncio.run(
        astart_confirmed_audit(
            inventory_dir,
            client_name,
            plan,
            settings=settings,
            agents_dir=agents_dir,
            note=note,
            executor=executor,
            discoverer=discoverer,
            refresh_discovery=refresh_discovery,
        )
    )


def _safe_inventory_dump(inventory: ClientInventory) -> dict[str, Any]:
    """Serialize inventory without embedding secret values."""
    data = inventory.model_dump()
    for cred in data.get("credentials") or []:
        if isinstance(cred, dict):
            cred.pop("secret", None)
            cred.pop("password", None)
    blob = json.dumps(data)
    # Defense in depth: never serialize obvious secret markers from values.
    if "password" in blob.lower() and "password_encryption" not in blob.lower():
        # Strip any accidental password-shaped keys from nested dumps.
        for cred in data.get("credentials") or []:
            if isinstance(cred, dict):
                for key in list(cred):
                    if "password" in key.lower() or key.lower() in {"secret", "token"}:
                        if key not in {"secret_ref", "has_secret"}:
                            cred.pop(key, None)
    return data


__all__ = [
    "InventoryLoadError",
    "PlanConfirmationRejected",
    "analyze_client_inventory",
    "confirm_audit_plan",
    "generate_audit_plan",
    "load_client_inventory",
    "load_effective_inventory",
    "load_plan",
    "persist_effective_inventory",
    "persist_plan",
    "plan_confirmation_prompt",
    "plans_dir_for",
    "astart_confirmed_audit",
    "plan_to_audit_request_payload",
    "reject_audit_launch",
    "resolve_effective_inventory",
    "start_confirmed_audit",
    "validate_client_inventory",
]

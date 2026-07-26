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
    reconcile_inventory,
)
from auditor.inventory.loaders import InventoryLoadError, load_raw_inventory
from auditor.inventory.normalize import normalize_inventory
from auditor.inventory.plan import (
    assert_plan_matches_inventory,
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

AuditExecutor = Callable[[Any], Awaitable[dict[str, Any]]]


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
) -> tuple[ClientInventory, AuditPlan]:
    """Validate inventory, run optional discovery, and generate a draft plan."""
    inventory = load_client_inventory(inventory_dir, client_name)
    collector = discoverer or NoopDiscoveryCollector()
    discoveries = collector.discover(inventory)
    if discoveries:
        inventory = reconcile_inventory(inventory, discoveries)
    detections = detect_technologies(inventory)
    plan = build_plan(inventory, detections, agents_dir=agents_dir)
    if persist_dir is not None:
        root = Path(persist_dir)
        persist_plan(plan, root / f"{plan.plan_id}.json")
        (root / f"{inventory.version.version_id}.inventory.json").write_text(
            json.dumps(_safe_inventory_dump(inventory), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return inventory, plan


def generate_audit_plan(
    inventory_dir: Path | str,
    client_name: str,
    *,
    agents_dir: Path | str | None = None,
    discoverer: DiscoveryCollector | None = None,
) -> AuditPlan:
    """Convenience wrapper returning only the draft plan."""
    _inventory, plan = analyze_client_inventory(
        inventory_dir,
        client_name,
        agents_dir=agents_dir,
        discoverer=discoverer,
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

    When ``action`` is ``approve``, reloads inventory (unless provided) and
    rejects with ``plan_stale`` if the inventory hash/version diverged.
    """
    if action == "approve":
        current = inventory
        if current is None:
            if inventory_dir is None or client_name is None:
                raise PlanConfirmationRejected(
                    "inventory_dir and client_name are required to confirm a plan",
                    code="missing_inventory_context",
                )
            current = load_client_inventory(inventory_dir, client_name)
        assert_plan_matches_inventory(plan, current)

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
    ``list_client_ssh_targets`` can resolve them. Client-level frameworks are
    attached to each host target.
    """
    ensure_plan_confirmed(plan)
    assert_plan_matches_inventory(plan, inventory)

    host_by_id = {h.host_id: h for h in inventory.hosts}
    by_ref: dict[str, list[dict[str, str]]] = {}
    client_frameworks: list[dict[str, str]] = []

    for target in plan.active_targets:
        pair = {
            "framework_id": target.framework_id,
            "framework_version": target.framework_version or "0",
        }
        if target.target_id.startswith("client:"):
            if pair not in client_frameworks:
                client_frameworks.append(pair)
            continue
        host = host_by_id.get(target.host_id)
        if host is None:
            continue
        ref = (host.address or host.host_id).strip()
        by_ref.setdefault(ref, [])
        if pair not in by_ref[ref]:
            by_ref[ref].append(pair)

    if client_frameworks:
        if by_ref:
            for ref in by_ref:
                for pair in client_frameworks:
                    if pair not in by_ref[ref]:
                        by_ref[ref].append(pair)
        else:
            raise PlanConfirmationRejected(
                "confirmed plan has only client-level targets and no host targets",
                code="empty_plan",
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
) -> dict[str, Any]:
    """Confirm a fresh plan and execute it via ``arun_request`` (or ``executor``).

    Returns a dict including ``audit_run_id``, ``plan_id``, and ``audit_request``.
    """
    settings = settings or load_settings()
    inventory_dir = Path(inventory_dir)
    client_name = validate_client_name(client_name)

    # Reload inventory; discovery is not re-run on start (plan already embeds
    # reconciled decisions). Stale check uses current inventory file hash.
    inventory = load_client_inventory(inventory_dir, client_name)
    # If the stored plan was built after discovery, its hash includes only the
    # file-backed inventory version from analyze time. Re-analyze path stores
    # the same file hash on the plan (discovery does not change content_hash
    # of the file). Stale = file changed.
    assert_plan_matches_inventory(plan, inventory)

    registry = get_client_registry(settings.evidence_dir)
    client = registry.ensure_client(display_name=client_name, slug=client_name)

    # Optional re-discovery for callers that inject a collector (tests / preflight).
    if discoverer is not None:
        inventory, plan = analyze_client_inventory(
            inventory_dir,
            client_name,
            agents_dir=agents_dir or settings.agents_dir,
            discoverer=discoverer,
        )

    if plan.status != "confirmed":
        plan = confirm_audit_plan(
            plan,
            action="approve",
            note=note or "confirmed",
            inventory=inventory,
        )
    else:
        assert_plan_matches_inventory(plan, inventory)

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

    async def _run() -> dict[str, Any]:
        return await run_executor(request)

    result: dict[str, Any] = asyncio.run(_run())
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
    "load_plan",
    "persist_plan",
    "plan_confirmation_prompt",
    "plan_to_audit_request_payload",
    "reject_audit_launch",
    "start_confirmed_audit",
    "validate_client_inventory",
]

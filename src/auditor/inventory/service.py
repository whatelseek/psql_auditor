"""High-level inventory analyze → plan → confirm → AuditRequest workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from auditor.domain.audit_plan import (
    AuditPlan,
    PlanConfirmationRejected,
    PlanConfirmationRequest,
)
from auditor.domain.audit_request import (
    AUDIT_REQUEST_SCHEMA_VERSION,
    POC_TOOL_PROFILE,
)
from auditor.domain.inventory import ClientInventory
from auditor.inventory.client_name import validate_client_name
from auditor.inventory.detect import detect_technologies
from auditor.inventory.loaders import InventoryLoadError, load_raw_inventory
from auditor.inventory.normalize import normalize_inventory
from auditor.inventory.plan import (
    confirm_audit_plan as apply_plan_confirmation,
)
from auditor.inventory.plan import (
    ensure_plan_confirmed,
    load_plan,
    persist_plan,
    plan_confirmation_prompt,
)
from auditor.inventory.plan import (
    generate_audit_plan as build_plan,
)


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
) -> tuple[ClientInventory, AuditPlan]:
    """Validate inventory, detect technologies, and generate a draft plan."""
    inventory = load_client_inventory(inventory_dir, client_name)
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
) -> AuditPlan:
    """Convenience wrapper returning only the draft plan."""
    _inventory, plan = analyze_client_inventory(inventory_dir, client_name, agents_dir=agents_dir)
    return plan


def confirm_audit_plan(
    plan: AuditPlan,
    *,
    action: str = "approve",
    host_ids: list[str] | None = None,
    framework_ids: list[str] | None = None,
    note: str = "",
) -> AuditPlan:
    """Confirm, reject, or adjust a draft plan."""
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
    inventory_ref: str = "INVENTORY.md",
    report_language: str = "en",
    hitl_enabled: bool = True,
    archive_enabled: bool = True,
    max_parallel_assessments: int = 5,
    max_parallel_host_jobs: int = 2,
) -> dict[str, Any]:
    """Convert a confirmed plan into an INPUT-001 AuditRequest payload.

    Groups frameworks by host inventory target. Client-level infrastructure
    targets are attached to a synthetic ``client:<id>`` inventory ref only when
    no host targets exist; otherwise host jobs carry OS/service frameworks.
    """
    ensure_plan_confirmed(plan)
    by_host: dict[str, list[dict[str, str]]] = {}
    for target in plan.active_targets:
        if target.target_id.startswith("client:"):
            # Keep general assessment as its own target ref.
            key = target.target_id
        else:
            key = target.host_id
        by_host.setdefault(key, [])
        pair = {
            "framework_id": target.framework_id,
            "framework_version": target.framework_version or "0",
        }
        if pair not in by_host[key]:
            by_host[key].append(pair)

    if not by_host:
        raise PlanConfirmationRejected(
            "confirmed plan has no executable targets",
            code="empty_plan",
        )

    targets = [
        {
            "inventory_target_ref": host_ref,
            "frameworks": frameworks,
        }
        for host_ref, frameworks in by_host.items()
    ]
    return {
        "schema_version": AUDIT_REQUEST_SCHEMA_VERSION,
        "client_id": plan.client_id,
        "inventory": {"kind": "client_file", "ref": inventory_ref},
        "targets": targets,
        "tool_profile": POC_TOOL_PROFILE,
        "run_settings": {
            "report_language": report_language,
            "hitl_enabled": hitl_enabled,
            "archive_enabled": archive_enabled,
            "max_parallel_assessments": max_parallel_assessments,
            "max_parallel_host_jobs": max_parallel_host_jobs,
        },
    }


def _safe_inventory_dump(inventory: ClientInventory) -> dict[str, Any]:
    """Serialize inventory without embedding secret values."""
    data = inventory.model_dump()
    for cred in data.get("credentials") or []:
        if isinstance(cred, dict):
            cred.pop("secret", None)
            cred.pop("password", None)
            # secret_ref is allowed; plaintext never present on the model.
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
    "validate_client_inventory",
]

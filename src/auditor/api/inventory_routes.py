"""HTTP API for inventory-driven audit planning lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from auditor.domain.audit_plan import PlanConfirmationRejected
from auditor.inventory.client_name import InvalidClientNameError
from auditor.inventory.loaders import InventoryLoadError
from auditor.inventory.plan import persist_plan, plan_confirmation_prompt
from auditor.inventory.service import (
    analyze_client_inventory,
    confirm_audit_plan,
    load_plan,
    plan_to_audit_request_payload,
    validate_client_inventory,
)

router = APIRouter(tags=["inventory-audit"])


class ConfirmBody(BaseModel):
    action: str = "approve"
    host_ids: list[str] = Field(default_factory=list)
    framework_ids: list[str] = Field(default_factory=list)
    note: str = ""


def _plans_dir(inventory_dir: Path, client: str) -> Path:
    return inventory_dir / client / ".audit_plans"


def _settings(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(status_code=503, detail="runtime not ready")
    return runtime.settings


@router.post("/clients/{client_id}/inventory/analyze")
async def analyze_inventory(client_id: str, request: Request) -> dict[str, Any]:
    settings = _settings(request)
    try:
        inventory, plan = analyze_client_inventory(
            settings.inventory_dir,
            client_id,
            agents_dir=settings.agents_dir,
            persist_dir=_plans_dir(Path(settings.inventory_dir), client_id),
        )
    except InvalidClientNameError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InventoryLoadError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    persist_plan(plan, _plans_dir(Path(settings.inventory_dir), client_id) / "latest.json")
    return {
        "inventory_version": inventory.version.model_dump(),
        "plan": plan.model_dump(),
        "confirmation_prompt": plan_confirmation_prompt(plan),
    }


@router.post("/clients/{client_id}/inventory")
async def validate_inventory(client_id: str, request: Request) -> dict[str, Any]:
    settings = _settings(request)
    try:
        inventory = validate_client_inventory(settings.inventory_dir, client_id)
    except InvalidClientNameError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InventoryLoadError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "client_id": inventory.client_id,
        "version": inventory.version.model_dump(),
        "hosts": [h.model_dump() for h in inventory.hosts],
        "issues": [i.model_dump() for i in inventory.issues],
        "credentials": [
            {
                **c.model_dump(),
                # Defensive: never expose unexpected secret-shaped keys.
            }
            for c in inventory.credentials
        ],
    }


@router.post("/clients/{client_id}/audit-plans")
async def create_audit_plan(client_id: str, request: Request) -> dict[str, Any]:
    return await analyze_inventory(client_id, request)


@router.post("/audit-plans/{plan_id}/confirm")
async def confirm_plan(plan_id: str, body: ConfirmBody, request: Request) -> dict[str, Any]:
    settings = _settings(request)
    inventory_root = Path(settings.inventory_dir)
    plan_path = None
    for client_dir in inventory_root.iterdir() if inventory_root.is_dir() else []:
        candidate = client_dir / ".audit_plans" / "latest.json"
        if candidate.is_file():
            plan = load_plan(candidate)
            if plan.plan_id == plan_id:
                plan_path = candidate
                break
    if plan_path is None:
        raise HTTPException(status_code=404, detail=f"plan {plan_id!r} not found")
    try:
        updated = confirm_audit_plan(
            load_plan(plan_path),
            action=body.action,
            host_ids=body.host_ids,
            framework_ids=body.framework_ids,
            note=body.note,
        )
    except PlanConfirmationRejected as exc:
        raise HTTPException(status_code=400, detail=exc.to_dict()) from exc
    persist_plan(updated, plan_path)
    result: dict[str, Any] = {"plan": updated.model_dump()}
    if updated.status == "confirmed":
        result["audit_request"] = plan_to_audit_request_payload(updated)
    return result

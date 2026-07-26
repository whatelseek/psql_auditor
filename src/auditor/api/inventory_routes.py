"""HTTP API for inventory-driven audit planning lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from auditor.client_registry import get_client_registry
from auditor.domain.audit_plan import PlanConfirmationRejected
from auditor.domain.audit_request import AuditRequestRejected
from auditor.inventory.client_name import InvalidClientNameError
from auditor.inventory.loaders import InventoryLoadError
from auditor.inventory.plan import persist_plan, plan_confirmation_prompt
from auditor.inventory.service import (
    analyze_client_inventory,
    astart_confirmed_audit,
    confirm_audit_plan,
    load_client_inventory,
    load_plan,
    plan_to_audit_request_payload,
    validate_client_inventory,
)

router = APIRouter(tags=["inventory-audit"])


class AnalyzeBody(BaseModel):
    """Optional analyze options. Discovery is enabled by default."""

    discovery: bool = True


class ConfirmBody(BaseModel):
    action: str = "approve"
    host_ids: list[str] = Field(default_factory=list)
    framework_ids: list[str] = Field(default_factory=list)
    note: str = ""
    start: bool = False
    refresh_discovery: bool = False


def _plans_dir(inventory_dir: Path, client: str) -> Path:
    return inventory_dir / client / ".audit_plans"


def _settings(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(status_code=503, detail="runtime not ready")
    return runtime.settings


async def _read_analyze_body(request: Request) -> AnalyzeBody:
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        return AnalyzeBody()
    if not isinstance(payload, dict):
        return AnalyzeBody()
    return AnalyzeBody.model_validate(payload)


@router.post("/clients/{client_id}/inventory/analyze")
async def analyze_inventory(client_id: str, request: Request) -> dict[str, Any]:
    settings = _settings(request)
    body = await _read_analyze_body(request)
    try:
        inventory, plan = analyze_client_inventory(
            settings.inventory_dir,
            client_id,
            agents_dir=settings.agents_dir,
            persist_dir=_plans_dir(Path(settings.inventory_dir), client_id),
            discovery=body.discovery,
            artifacts_root=settings.evidence_dir,
        )
    except InvalidClientNameError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InventoryLoadError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    persist_plan(plan, _plans_dir(Path(settings.inventory_dir), client_id) / "latest.json")
    return {
        "inventory_version": inventory.version.model_dump(),
        "plan": plan.model_dump(),
        "conflicts": [c.model_dump() for c in inventory.conflicts],
        "confirmation_prompt": plan_confirmation_prompt(plan),
        "discovery_enabled": body.discovery,
        "preflight_revision_id": plan.preflight_revision_id,
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
        "credentials": [c.model_dump() for c in inventory.credentials],
    }


@router.post("/clients/{client_id}/audit-plans")
async def create_audit_plan(client_id: str, request: Request) -> dict[str, Any]:
    return await analyze_inventory(client_id, request)


@router.post("/audit-plans/{plan_id}/confirm")
async def confirm_plan(plan_id: str, body: ConfirmBody, request: Request) -> dict[str, Any]:
    settings = _settings(request)
    inventory_root = Path(settings.inventory_dir)
    plan_path = None
    client_name = ""
    for client_dir in inventory_root.iterdir() if inventory_root.is_dir() else []:
        candidate = client_dir / ".audit_plans" / "latest.json"
        if candidate.is_file():
            plan = load_plan(candidate)
            if plan.plan_id == plan_id:
                plan_path = candidate
                client_name = client_dir.name
                break
    if plan_path is None:
        raise HTTPException(status_code=404, detail=f"plan {plan_id!r} not found")

    try:
        inventory = load_client_inventory(settings.inventory_dir, client_name)
        if body.action == "approve" and body.start:
            started = await astart_confirmed_audit(
                settings.inventory_dir,
                client_name,
                load_plan(plan_path),
                settings=settings,
                agents_dir=settings.agents_dir,
                note=body.note,
                executor=_runtime_executor(request),
                refresh_discovery=body.refresh_discovery,
            )
            persist_plan(started["plan"], plan_path)
            return {
                "plan": started["plan"].model_dump(),
                "audit_run_id": started["audit_run_id"],
                "client_id": started["client_id"],
                "audit_request": started["audit_request"],
            }

        updated = confirm_audit_plan(
            load_plan(plan_path),
            action=body.action,
            host_ids=body.host_ids,
            framework_ids=body.framework_ids,
            note=body.note,
            inventory=inventory if body.action == "approve" else None,
            inventory_dir=settings.inventory_dir,
            client_name=client_name,
        )
    except PlanConfirmationRejected as exc:
        status = 409 if getattr(exc, "code", "") == "plan_stale" else 400
        raise HTTPException(status_code=status, detail=exc.to_dict()) from exc
    except (InvalidClientNameError, InventoryLoadError, AuditRequestRejected) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    persist_plan(updated, plan_path)
    result: dict[str, Any] = {"plan": updated.model_dump()}
    if updated.status == "confirmed":
        client = get_client_registry(settings.evidence_dir).ensure_client(
            display_name=client_name,
            slug=client_name,
        )
        result["audit_request"] = plan_to_audit_request_payload(
            updated,
            inventory=inventory,
            client_id=client.client_id,
            client_slug=client.slug,
        )
    return result


def _runtime_executor(request: Request):
    runtime = getattr(request.app.state, "runtime", None)

    async def _execute(req: Any) -> dict[str, Any]:
        if runtime is None:
            raise HTTPException(status_code=503, detail="runtime not ready")
        # ApplicationRuntime exposes the graph via attribute used by openai_compat.
        graph = getattr(runtime, "graph", None) or getattr(runtime, "auditor", None)
        if graph is not None and hasattr(graph, "arun_request"):
            return await graph.arun_request(req, operator_context="API inventory-driven start")
        from auditor.graph import AuditorGraph

        return await AuditorGraph(settings=runtime.settings).arun_request(
            req, operator_context="API inventory-driven start"
        )

    return _execute

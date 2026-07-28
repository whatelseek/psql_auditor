"""CLI for inventory-driven audit launch (``psql-auditor`` / ``auditor-cli``).

Examples::

    psql-auditor inventory validate Testcompany
    psql-auditor inventory analyze Testcompany
    psql-auditor audit plan Testcompany
    psql-auditor audit start Testcompany --confirm
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from auditor.config import load_settings
from auditor.domain.audit_plan import PlanConfirmationRejected
from auditor.domain.audit_request import AuditRequestRejected
from auditor.inventory.client_name import InvalidClientNameError
from auditor.inventory.loaders import InventoryLoadError
from auditor.inventory.plan import plan_confirmation_prompt
from auditor.inventory.service import (
    analyze_client_inventory,
    confirm_audit_plan,
    load_client_inventory,
    load_plan,
    persist_plan,
    reject_audit_launch,
    resolve_effective_inventory,
    start_confirmed_audit,
    validate_client_inventory,
)


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def _plans_dir(settings_inventory: Path, client: str) -> Path:
    return Path(settings_inventory) / client / ".audit_plans"


def cmd_inventory_validate(args: argparse.Namespace) -> int:
    settings = load_settings()
    try:
        inventory = validate_client_inventory(settings.inventory_dir, args.client)
    except (InvalidClientNameError, InventoryLoadError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = {
        "client_id": inventory.client_id,
        "version": inventory.version.model_dump(),
        "hosts": len(inventory.hosts),
        "error_count": inventory.error_count,
        "warning_count": inventory.warning_count,
        "issues": [i.model_dump() for i in inventory.issues],
        "credentials": [c.model_dump() for c in inventory.credentials],
    }
    _print_json(payload)
    return 1 if inventory.error_count else 0


def cmd_inventory_analyze(args: argparse.Namespace) -> int:
    settings = load_settings()
    plans = _plans_dir(Path(settings.inventory_dir), args.client)
    try:
        inventory, plan = analyze_client_inventory(
            settings.inventory_dir,
            args.client,
            agents_dir=settings.agents_dir,
            persist_dir=plans,
            discovery=not args.no_discovery,
            artifacts_root=settings.evidence_dir,
        )
    except (InvalidClientNameError, InventoryLoadError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    persist_plan(plan, plans / "latest.json")
    _print_json(
        {
            "inventory_version": inventory.version.model_dump(),
            "summary": plan.summary.model_dump(),
            "plan_id": plan.plan_id,
            "status": plan.status,
            "detections": [d.model_dump() for d in plan.technology_detections],
            "framework_decisions": [d.model_dump() for d in plan.framework_decisions],
            "conflicts": [c.model_dump() for c in inventory.conflicts],
            "confirmation_prompt": plan_confirmation_prompt(plan),
            "discovery_enabled": not args.no_discovery,
            "preflight_revision_id": plan.preflight_revision_id,
        }
    )
    return 0


def cmd_audit_plan(args: argparse.Namespace) -> int:
    settings = load_settings()
    plans = _plans_dir(Path(settings.inventory_dir), args.client)
    latest = plans / "latest.json"
    if latest.is_file() and not args.refresh:
        plan = load_plan(latest)
        # Surface stale plans before the operator confirms.
        try:
            inventory = resolve_effective_inventory(settings.inventory_dir, args.client)
            from auditor.inventory.plan import assert_plan_matches_inventory

            assert_plan_matches_inventory(plan, inventory)
            source = load_client_inventory(settings.inventory_dir, args.client)
            assert_plan_matches_inventory(plan, source)
        except PlanConfirmationRejected as exc:
            print(f"warning: {exc}", file=sys.stderr)
            print("Re-run with --refresh to regenerate the plan.", file=sys.stderr)
            return 4
        except (InvalidClientNameError, InventoryLoadError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        _inventory, plan = analyze_client_inventory(
            settings.inventory_dir,
            args.client,
            agents_dir=settings.agents_dir,
            persist_dir=plans,
            discovery=not args.no_discovery,
            artifacts_root=settings.evidence_dir,
        )
        persist_plan(plan, latest)
    print(plan_confirmation_prompt(plan))
    print()
    _print_json(plan.model_dump())
    return 0


def cmd_audit_start(args: argparse.Namespace) -> int:
    settings = load_settings()
    plans = _plans_dir(Path(settings.inventory_dir), args.client)
    latest = plans / "latest.json"
    if not latest.is_file():
        print(
            "error: no draft plan found; run `audit plan` / `inventory analyze` first",
            file=sys.stderr,
        )
        return 2
    plan = load_plan(latest)
    if args.reject:
        plan = confirm_audit_plan(
            plan,
            action="reject",
            note=args.note or "rejected via CLI",
        )
        persist_plan(plan, latest)
        print("audit launch rejected by operator")
        return 1
    if not args.confirm:
        try:
            reject_audit_launch(plan)
        except PlanConfirmationRejected as exc:
            print(f"error: {exc}", file=sys.stderr)
            print(plan_confirmation_prompt(plan), file=sys.stderr)
            print("\nRe-run with --confirm to approve the plan.", file=sys.stderr)
            return 3
        # Confirmed earlier — still require freshness before execute.
    try:
        started = start_confirmed_audit(
            settings.inventory_dir,
            args.client,
            plan,
            settings=settings,
            agents_dir=settings.agents_dir,
            note=args.note or "confirmed via CLI",
            refresh_discovery=bool(args.refresh_discovery),
        )
    except PlanConfirmationRejected as exc:
        print(f"error: {exc}", file=sys.stderr)
        if getattr(exc, "code", "") in {"plan_stale", "audit_plan_stale"}:
            print("Re-run `inventory analyze` / `audit plan --refresh`.", file=sys.stderr)
            return 4
        return 3
    except (InvalidClientNameError, InventoryLoadError, AuditRequestRejected) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = plans / "audit_request.json"
    out.write_text(
        json.dumps(started["audit_request"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if started.get("plan") is not None:
        persist_plan(started["plan"], latest)
    _print_json(
        {
            "status": started["status"],
            "plan_id": started["plan_id"],
            "client_id": started["client_id"],
            "audit_run_id": started["audit_run_id"],
            "evidence_run_id": started.get("evidence_run_id"),
            "audit_run_status": started.get("audit_run_status"),
            "awaiting_hitl": started.get("awaiting_hitl"),
            "audit_request_path": str(out),
            "audit_request": started["audit_request"],
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psql-auditor",
        description="Inventory-driven infrastructure audit launcher",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="Inventory load / validate / analyze")
    inv_sub = inv.add_subparsers(dest="inventory_command", required=True)
    p_val = inv_sub.add_parser("validate", help="Validate client inventory")
    p_val.add_argument("client")
    p_val.set_defaults(func=cmd_inventory_validate)
    p_an = inv_sub.add_parser("analyze", help="Analyze inventory and draft a plan")
    p_an.add_argument("client")
    p_an.add_argument(
        "--no-discovery",
        action="store_true",
        help="Disable live SSH/WinRM discovery (use inventory facts only)",
    )
    p_an.set_defaults(func=cmd_inventory_analyze)

    audit = sub.add_parser("audit", help="Audit plan confirmation and launch")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    p_plan = audit_sub.add_parser("plan", help="Show / refresh the draft audit plan")
    p_plan.add_argument("client")
    p_plan.add_argument("--refresh", action="store_true")
    p_plan.add_argument(
        "--no-discovery",
        action="store_true",
        help="When refreshing, skip live discovery",
    )
    p_plan.set_defaults(func=cmd_audit_plan)
    p_start = audit_sub.add_parser(
        "start",
        help="Confirm plan (when --confirm) and start audit execution via arun_request",
    )
    p_start.add_argument("client")
    p_start.add_argument("--confirm", action="store_true", help="Approve the draft plan")
    p_start.add_argument("--reject", action="store_true", help="Reject the draft plan")
    p_start.add_argument("--note", default="")
    p_start.add_argument(
        "--refresh-discovery",
        action="store_true",
        help="Re-run discovery and reject the plan if effective facts changed",
    )
    p_start.set_defaults(func=cmd_audit_start)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

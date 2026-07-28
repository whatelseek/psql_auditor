"""CLI for inventory-driven audit launch (``psql-auditor`` / ``auditor-cli``).

Examples::

    psql-auditor inventory validate Testcompany
    psql-auditor inventory analyze Testcompany
    psql-auditor audit plan Testcompany
    psql-auditor audit start Testcompany --confirm --plan-revision-id prev-...
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
from auditor.inventory.plan_store import PlanRevisionStore, PlanStoreError
from auditor.inventory.service import (
    analyze_client_inventory,
    confirm_audit_plan,
    load_client_inventory,
    reject_audit_launch,
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
    except (InvalidClientNameError, InventoryLoadError, PlanStoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, PlanStoreError) and exc.code == "plan_store_lock_failed":
            return 5
        return 2
    _print_json(
        {
            "inventory_version": inventory.version.model_dump(),
            "summary": plan.summary.model_dump(),
            "plan_id": plan.plan_id,
            "plan_revision_id": plan.plan_revision_id,
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
    store = PlanRevisionStore(plans)
    if not args.refresh:
        try:
            snapshot = store.load_latest()
            plan = snapshot.plan
            inventory = snapshot.effective_inventory
            from auditor.inventory.plan import assert_plan_matches_inventory

            assert_plan_matches_inventory(plan, inventory)
            source = load_client_inventory(settings.inventory_dir, args.client)
            assert_plan_matches_inventory(plan, source)
        except PlanStoreError as exc:
            if exc.code != "plan_revision_not_found":
                print(f"error: {exc}", file=sys.stderr)
                if exc.code == "plan_store_lock_failed":
                    return 5
                return 2
            # No stored revision yet — generate one.
            _inventory, plan = analyze_client_inventory(
                settings.inventory_dir,
                args.client,
                agents_dir=settings.agents_dir,
                persist_dir=plans,
                discovery=not args.no_discovery,
                artifacts_root=settings.evidence_dir,
            )
        except PlanConfirmationRejected as exc:
            print(f"warning: {exc}", file=sys.stderr)
            print("Re-run with --refresh to regenerate the plan.", file=sys.stderr)
            return 4
        except (InvalidClientNameError, InventoryLoadError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        else:
            print(plan_confirmation_prompt(plan))
            print()
            _print_json(plan.model_dump())
            return 0
        print(plan_confirmation_prompt(plan))
        print()
        _print_json(plan.model_dump())
        return 0

    _inventory, plan = analyze_client_inventory(
        settings.inventory_dir,
        args.client,
        agents_dir=settings.agents_dir,
        persist_dir=plans,
        discovery=not args.no_discovery,
        artifacts_root=settings.evidence_dir,
    )
    print(plan_confirmation_prompt(plan))
    print()
    _print_json(plan.model_dump())
    return 0


def _cli_plan_error(exc: PlanConfirmationRejected) -> int:
    print(f"error: {exc}", file=sys.stderr)
    code = getattr(exc, "code", "")
    if code in {"plan_stale", "audit_plan_stale"}:
        print("Re-run `inventory analyze` / `audit plan --refresh`.", file=sys.stderr)
        return 4
    if code in {"plan_revision_not_found", "invalid_plan_pointer"}:
        return 2
    if code == "plan_store_lock_failed":
        return 5
    return 3


def cmd_audit_start(args: argparse.Namespace) -> int:
    settings = load_settings()
    plans = _plans_dir(Path(settings.inventory_dir), args.client)
    store = PlanRevisionStore(plans)
    try:
        snapshot = store.load_revision(args.plan_revision_id)
    except PlanConfirmationRejected as exc:
        return _cli_plan_error(exc)

    plan = snapshot.plan
    if args.reject:
        try:
            store.assert_current(args.plan_revision_id)
            plan = confirm_audit_plan(
                plan,
                action="reject",
                note=args.note or "rejected via CLI",
                expected_plan_revision_id=args.plan_revision_id,
            )
            store.persist_latest_materialized_plan(
                plan,
                expected_plan_revision_id=args.plan_revision_id,
            )
        except PlanConfirmationRejected as exc:
            return _cli_plan_error(exc)
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
            expected_plan_revision_id=args.plan_revision_id,
        )
    except PlanConfirmationRejected as exc:
        return _cli_plan_error(exc)
    except (InvalidClientNameError, InventoryLoadError, AuditRequestRejected) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = plans / "audit_request.json"
    out.write_text(
        json.dumps(started["audit_request"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _print_json(
        {
            "status": started["status"],
            "plan_id": started["plan_id"],
            "plan_revision_id": started["plan"].plan_revision_id,
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
    p_start.add_argument(
        "--plan-revision-id",
        required=True,
        help="Exact plan revision shown by inventory analyze or audit plan",
    )
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

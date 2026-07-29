"""Multi-host / multi-framework scheduling and report merge."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from langchain_core.messages import AIMessage

from auditor.asset_registry import get_asset_registry
from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry
from auditor.compliance import format_chat_summary_visuals, parse_report_findings
from auditor.config import Settings
from auditor.context import truncate_text
from auditor.domain import (
    AuditJobStatus,
    AuditJobType,
    AuditRequest,
    AuditRequestIssue,
    AuditRequestRejected,
    AuditRunStatus,
    JobErrorInfo,
    build_audit_request_from_selected_jobs,
    persistable_audit_request,
    resolve_inventory_target,
    scope_with_audit_request,
    validate_audit_request_semantics,
)
from auditor.evidence_store import EvidenceStore, new_run_id
from auditor.followup import followup_footer
from auditor.frameworks import get_framework
from auditor.host_facts import HostFacts, parse_host_facts_json
from auditor.intake import (
    clear_active_intake_pause,
    client_slug,
    filter_scope_framework_ids,
)
from auditor.language import detect_report_language
from auditor.legacy_compat import ClientOwnershipError, MissingAuditRunIdError, require_audit_run_id
from auditor.report_archive import package_and_publish_archive
from auditor.results_store import start_session_safe
from auditor.run_scope import checkpoint_thread_id, evidence_run_id_for
from auditor.secrets_file import InventorySshTarget, list_client_ssh_targets
from auditor.session_store import drop_multi_session, load_all_multi_sessions, save_multi_session
from auditor.workflows.protocols import AuditRuntime


async def schedule_framework_jobs(
    runtime: AuditRuntime,
    *,
    user_text: str,
    base_thread: str,
    run_id: str,
    intake_state: dict[str, Any] | None,
    pending_jobs: list[dict[str, Any]],
    completed: list[tuple[str, str, str]],
    plan_md: str,
) -> dict[str, Any]:
    """Run pending host/framework jobs with host-exclusive concurrency.

    Up to ``max_parallel_host_jobs`` graphs run at once, but at most one job
    per host slug. On HITL, new starts stop; in-flight jobs drain; the first
    paused job is returned with remaining work recorded for resume.
    """
    pending = list(pending_jobs)
    if not pending:
        merged = await runtime._merge_multi_reports(
            completed,
            run_id=run_id,
            base_thread=base_thread,
            audit_run_id=str((intake_state or {}).get("audit_run_id") or "") or None,
        )
        return merged

    limit = max(1, int(runtime.settings.max_parallel_host_jobs))
    completed_list = list(completed)
    stop_starting = False
    in_flight: dict[asyncio.Task[dict[str, Any]], dict[str, Any]] = {}
    busy_hosts: set[str] = set()
    hitl_paused: list[dict[str, Any]] = []

    def _session_payload(
        job: dict[str, Any],
        *,
        remaining: list[dict[str, Any]],
        siblings: list[dict[str, Any]] | None = None,
        hitl_report: str = "",
    ) -> dict[str, Any]:
        """Build multi-session orchestration state for one job thread."""
        return {
            "base_thread": base_thread,
            "run_id": run_id,
            "audit_run_id": str(
                (intake_state or {}).get("audit_run_id") or job.get("audit_run_id") or ""
            ),
            "job_id": str(job.get("job_id") or ""),
            "user_text": user_text,
            "framework_id": str(job.get("framework_id") or ""),
            "framework_title": str(job.get("framework_title") or job.get("framework_id") or ""),
            "job_key": _job_dict_key(job),
            "evidence_host_id": str(job.get("evidence_host_id") or ""),
            "ssh_target": _target_from_job_dict(job, runtime.settings),
            "remaining_jobs": list(remaining),
            "remaining": [str(j.get("framework_id") or "") for j in remaining],
            "completed": list(completed_list),
            "intake_state": intake_state,
            "plan_md": plan_md,
            "paused_siblings": list(siblings or []),
            "hitl_report": hitl_report,
            "parallel_scheduler": True,
        }

    registry = get_audit_registry(runtime.settings.evidence_dir)
    audit_run_id = str((intake_state or {}).get("audit_run_id") or "")

    async def _run_one(job: dict[str, Any]) -> dict[str, Any]:
        """Invoke a single host/framework audit for the scheduler."""
        fw_id = str(job.get("framework_id") or "")
        host_id = str(job.get("evidence_host_id") or "")
        tid = _job_dict_thread_id(base_thread, job)
        logical = _job_dict_key(job)
        active_job = None
        if audit_run_id:
            latest = registry.latest_job_for_task(audit_run_id, logical)
            if latest is not None and latest.status == AuditJobStatus.RUNNING:
                # Same attempt (e.g. resume after HITL / reconnect).
                active_job = latest
                if tid and not active_job.thread_id:
                    active_job.thread_id = tid
                    registry.save_job(active_job)
            elif latest is not None and latest.status in {
                AuditJobStatus.FAILED,
                AuditJobStatus.CANCELLED,
            }:
                # Worker retry → new AuditJob attempt, same AuditRun.
                active_job = registry.retry_job(
                    audit_run_id=audit_run_id,
                    logical_task_id=logical,
                    thread_id=tid,
                    framework_id=fw_id,
                    host_id=host_id,
                    mandatory=True,
                )
            else:
                # Start pending attempt created at run start (or create first).
                active_job = registry.start_job_attempt(
                    audit_run_id=audit_run_id,
                    logical_task_id=logical,
                    thread_id=tid,
                    framework_id=fw_id,
                    host_id=host_id,
                    mandatory=True,
                    job_type=AuditJobType.ASSESS_FRAMEWORK,
                    new_attempt=False,
                )
            job["job_id"] = active_job.job_id
            job["audit_run_id"] = audit_run_id
            job["attempt"] = active_job.attempt
        try:
            job_intake = dict(intake_state or {})
            if job.get("asset_id"):
                job_intake["asset_id"] = str(job.get("asset_id"))
            if job.get("framework_version"):
                job_intake["framework_version"] = str(job.get("framework_version"))
            result = await runtime.arun_one(
                user_text,
                framework_id=fw_id,
                run_id=run_id,
                thread_id=tid,
                intake_state=job_intake,
                evidence_host_id=host_id or None,
                ssh_target=_target_from_job_dict(job, runtime.settings),
            )
        except Exception as exc:  # noqa: BLE001
            if active_job is not None:
                registry.fail_job(active_job.job_id, exc)
            raise
        if active_job is not None:
            if result.get("awaiting_hitl"):
                # Keep attempt running while operator decides.
                pass
            elif result.get("error"):
                registry.fail_job(
                    active_job.job_id,
                    JobErrorInfo(
                        error_type="AuditError",
                        message=str(result.get("error")),
                    ),
                )
            else:
                registry.complete_job(active_job.job_id)
        return result

    while pending or in_flight:
        while not stop_starting and len(in_flight) < limit and pending:
            started = False
            for index, job in enumerate(pending):
                host_key = _host_lock_key_from_job(job)
                if host_key in busy_hosts:
                    continue
                pending.pop(index)
                tid = _job_dict_thread_id(base_thread, job)
                runtime._remember_multi_session(
                    tid,
                    _session_payload(job, remaining=list(pending)),
                )
                task = asyncio.create_task(
                    _run_one(job),
                    name=f"host-job:{_job_dict_key(job)}",
                )
                in_flight[task] = {
                    "job": job,
                    "thread_id": tid,
                    "host_key": host_key,
                }
                busy_hosts.add(host_key)
                started = True
                break
            if not started:
                break

        if not in_flight:
            break

        done, _ = await asyncio.wait(
            set(in_flight.keys()),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            meta = in_flight.pop(task)
            busy_hosts.discard(str(meta["host_key"]))
            job = meta["job"]
            tid = str(meta["thread_id"])
            key = _job_dict_key(job)
            try:
                result = task.result()
            except Exception as exc:  # noqa: BLE001
                result = {
                    "report": (f"Host/framework job `{key}` failed: {type(exc).__name__}: {exc}"),
                    "awaiting_hitl": False,
                    "thread_id": tid,
                    "messages": [
                        AIMessage(
                            content=(
                                f"Host/framework job `{key}` failed: {type(exc).__name__}: {exc}"
                            )
                        )
                    ],
                }

            if result.get("awaiting_hitl"):
                stop_starting = True
                hitl_paused.append(
                    {
                        "job": job,
                        "thread_id": tid,
                        "result": result,
                        "job_key": key,
                    }
                )
                continue

            runtime._forget_multi_session(tid)
            completed_list.append((key, _job_display_title(job), result.get("report") or ""))

    if hitl_paused:
        siblings = [
            {
                "thread_id": item["thread_id"],
                "job_key": item["job_key"],
                "framework_id": str(item["job"].get("framework_id") or ""),
                "framework_title": str(
                    item["job"].get("framework_title") or item["job"].get("framework_id") or ""
                ),
                "evidence_host_id": str(item["job"].get("evidence_host_id") or ""),
            }
            for item in hitl_paused
        ]
        for item in hitl_paused:
            others = [s for s in siblings if s["thread_id"] != item["thread_id"]]
            report = str(item["result"].get("report") or "")
            runtime._remember_multi_session(
                str(item["thread_id"]),
                _session_payload(
                    item["job"],
                    remaining=list(pending),
                    siblings=others,
                    hitl_report=report,
                ),
            )
        primary = hitl_paused[0]
        prefix = runtime._multi_progress_preamble(
            completed_list,
            str(primary["job_key"]),
            in_flight_keys=[str(p["job_key"]) for p in hitl_paused[1:]],
            queued_keys=[_job_dict_key(j) for j in pending],
        )
        preamble = f"{plan_md}\n{prefix}" if plan_md else prefix
        result = dict(primary["result"])
        body = str(result.get("report") or "")
        report = f"{preamble}{body}" if preamble else body
        result["report"] = report
        result["awaiting_hitl"] = True
        result["thread_id"] = primary["thread_id"]
        result["messages"] = [AIMessage(content=report)]
        return result

    merged = await runtime._merge_multi_reports(
        completed_list,
        run_id=run_id,
        base_thread=base_thread,
        audit_run_id=audit_run_id or None,
    )
    if plan_md:
        merged["report"] = f"{plan_md}\n{merged.get('report') or ''}"
    return merged


def _bootstrap_audit_run(
    runtime: AuditRuntime,
    *,
    run_id: str,
    base_thread: str,
    intake_state: dict[str, Any],
    pending: list[dict[str, Any]],
) -> dict[str, Any]:
    """Ensure AuditRun + pending AuditJobs for this execution (outside nodes).

    Reuses ``client_id`` / ``audit_run_id`` from intake when present (CORE-001).
    Never derives a run id from client name/slug.
    """
    updated = dict(intake_state)
    raw_intake = updated.get("intake")
    intake: dict[str, Any] = raw_intake if isinstance(raw_intake, dict) else {}
    display = str(updated.get("client_name") or intake.get("client_name") or "")
    slug = str(
        updated.get("client_slug") or intake.get("client_slug") or client_slug(display) or "client"
    )
    client = get_client_registry(runtime.settings.evidence_dir).ensure_client(
        display_name=display or slug,
        slug=slug,
        client_id=str(updated.get("client_id") or intake.get("client_id") or "") or None,
    )
    updated["client_id"] = client.client_id
    updated["client_slug"] = client.slug

    # INPUT-001: bind validated request before allocating/creating jobs.
    from auditor.domain import load_persisted_audit_request

    audit_request_raw = updated.get("audit_request") or (intake or {}).get("audit_request")
    bound_request = None
    if audit_request_raw:
        bound_request = load_persisted_audit_request(audit_request_raw)
        if bound_request.client_id != client.client_id:
            raise AuditRequestRejected(
                issues=[
                    AuditRequestIssue(
                        location="client_id",
                        code="client_ownership_mismatch",
                        message="AuditRequest.client_id does not own this audit run",
                    )
                ],
            )
    registry = get_audit_registry(runtime.settings.evidence_dir)
    audit_run_id = str(updated.get("audit_run_id") or intake.get("audit_run_id") or "").strip()
    if audit_run_id:
        require_audit_run_id(audit_run_id, context="_bootstrap_audit_run")
        arun = registry.get_run(audit_run_id)
        if arun is None:
            raise MissingAuditRunIdError(f"unknown audit_run_id {audit_run_id!r} in bootstrap")
        if arun.client_id and arun.client_id != client.client_id:
            raise ClientOwnershipError(
                f"audit_run_id {audit_run_id!r} belongs to client_id={arun.client_id!r}, "
                f"not {client.client_id!r}"
            )
        if not arun.evidence_run_id:
            arun.evidence_run_id = run_id
            registry.save_run(arun)

        audit_request_raw = updated.get("audit_request") or (intake or {}).get("audit_request")
        if audit_request_raw:
            try:
                from auditor.domain import load_persisted_audit_request

                req = load_persisted_audit_request(audit_request_raw)
                arun.scope = scope_with_audit_request(arun.scope, req)
                registry.save_run(arun)
            except AuditRequestRejected:
                pass
    else:
        # New audit without prior intake allocation (direct framework jobs).
        if pending and bound_request is None:
            raise AuditRequestRejected(
                issues=[
                    AuditRequestIssue(
                        location="audit_request",
                        code="typed_request_required",
                        message=(
                            "new AuditJob rows require a validated AuditRequest; "
                            "legacy free-text job creation is not allowed"
                        ),
                    )
                ],
            )
        scope = {
            "audit_types": str(updated.get("audit_types") or ""),
            "frameworks": [_job_dict_key(j) for j in pending],
            "has_access": bool(updated.get("has_access")),
            "client_name": display,
            "client_slug": client.slug,
            "selected_jobs": list((intake or {}).get("selected_jobs") or []),
        }
        audit_request_raw = updated.get("audit_request") or (intake or {}).get("audit_request")
        if audit_request_raw:
            try:
                from auditor.domain import load_persisted_audit_request

                req = load_persisted_audit_request(audit_request_raw)
                scope = scope_with_audit_request(scope, req)
            except AuditRequestRejected:
                pass
        session_number = updated.get("results_session_number")
        arun = registry.create_run(
            client_id=client.client_id,
            scope=scope,
            evidence_run_id=run_id,
            base_thread_id=base_thread,
            results_session_number=(int(session_number) if session_number is not None else None),
        )
        registry.mark_run_started(arun.audit_run_id)
        audit_run_id = arun.audit_run_id
    updated["audit_run_id"] = audit_run_id
    # CORE-005: after identity is known, prefer the canonical checkpoint base.
    # Callers may still pass a pre-identity base; jobs use the canonical key.
    updated["base_thread"] = checkpoint_thread_id(client.client_id, audit_run_id)
    # Nested evidence + ownership when a store exists for this run_id.
    store = runtime._evidence_by_run.get(run_id)
    if store is not None:
        nested = evidence_run_id_for(client.slug, audit_run_id)
        if store.run_id != nested:
            old = store.run_id
            store.rebind_run_id(
                nested,
                client_id=client.client_id,
                audit_run_id=audit_run_id,
            )
            runtime._evidence_by_run.pop(old, None)
            runtime._evidence_by_run[store.run_id] = store
            updated["evidence_run_id"] = store.run_id
            run_row = registry.get_run(audit_run_id)
            if run_row is not None:
                run_row.evidence_run_id = store.run_id
                run_row.base_thread_id = updated["base_thread"]
                registry.save_run(run_row)
        store.write_run_meta(
            client_id=client.client_id,
            client_slug=client.slug,
            audit_run_id=audit_run_id,
        )

    # Create pending jobs only once per logical task for this run.
    job_base = str(updated.get("base_thread") or base_thread)
    assets = get_asset_registry(runtime.settings.evidence_dir)
    for job in pending:
        logical = _job_dict_key(job)
        existing = registry.latest_job_for_task(audit_run_id, logical)
        if existing is None:
            if bound_request is None:
                raise AuditRequestRejected(
                    issues=[
                        AuditRequestIssue(
                            location="audit_request",
                            code="typed_request_required",
                            message=(
                                "new AuditJob rows require a validated AuditRequest; "
                                "legacy free-text job creation is not allowed"
                            ),
                        )
                    ],
                )
            created = registry.create_job(
                audit_run_id=audit_run_id,
                logical_task_id=logical,
                job_type=AuditJobType.ASSESS_FRAMEWORK,
                mandatory=True,
                thread_id=_job_dict_thread_id(job_base, job),
                framework_id=str(job.get("framework_id") or ""),
                host_id=str(job.get("evidence_host_id") or ""),
            )
        else:
            created = existing
        job["job_id"] = created.job_id
        job["audit_run_id"] = audit_run_id
        job["attempt"] = created.attempt
        label = str(job.get("ssh_label") or "").strip()
        host = str(job.get("ssh_host") or "").strip()
        inv_key = label or str(job.get("asset_id") or "").strip()
        if inv_key:
            job["asset_id"] = assets.ensure_asset(
                client_id=client.client_id,
                inventory_key=inv_key,
                label=label or inv_key,
                ssh_host=host,
                asset_id=str(job.get("asset_id") or "") or None,
            )
        elif not job.get("asset_id"):
            job["asset_id"] = assets.ensure_asset(
                client_id=client.client_id,
                inventory_key=f"client:{client.client_id}",
                label=display or client.slug,
            )
        if not job.get("framework_version"):
            fw_obj = get_framework(
                str(job.get("framework_id") or ""),
                runtime.settings.agents_dir,
            )
            job["framework_version"] = str(getattr(fw_obj, "version", "") or "")
    store = runtime._evidence_by_run.get(run_id)
    if store is not None:
        store.write_run_meta(
            audit_run_id=audit_run_id,
            client_id=client.client_id,
            client_slug=client.slug,
            client_name=display,
            status="running",
        )
    return updated


async def run_framework_jobs(
    runtime: AuditRuntime,
    *,
    user_text: str,
    base_thread: str,
    run_id: str,
    intake_state: dict[str, Any],
    jobs: list[tuple[InventorySshTarget | None, HostFacts | None, Any]],
    plan_md: str,
) -> dict[str, Any]:
    """Run (host, framework) audits with bounded cross-host parallelism."""
    if not jobs:
        return {
            "report": "No frameworks selected.",
            "messages": [AIMessage(content="No frameworks selected.")],
            "awaiting_hitl": False,
        }

    job_client_slug = str(intake_state.get("client_slug") or "")
    pending = [
        _serialize_host_job(target, fw, client_slug=job_client_slug) for target, _facts, fw in jobs
    ]
    intake_state = _bootstrap_audit_run(
        runtime,
        run_id=run_id,
        base_thread=base_thread,
        intake_state=intake_state,
        pending=pending,
    )
    canonical_base = str(intake_state.get("base_thread") or base_thread)
    evid = str(intake_state.get("evidence_run_id") or run_id)
    return await runtime._schedule_framework_jobs(
        user_text=user_text,
        base_thread=canonical_base,
        run_id=evid,
        intake_state=intake_state,
        pending_jobs=pending,
        completed=[],
        plan_md=plan_md,
    )


async def merge_multi_reports(
    runtime: AuditRuntime,
    completed: list[tuple[str, str, str]],
    *,
    run_id: str,
    base_thread: str,
    audit_run_id: str | None = None,
) -> dict[str, Any]:
    """Combine per-framework reports, write root report, and package ZIP.

    Prefers on-disk framework reports (survive HITL) over in-memory text.

    Args:
        completed: ``(framework_id, title, report)`` tuples in order.
        run_id: Shared evidence run id.
        base_thread: Parent thread id for the combined result.
        audit_run_id: Optional business-level AuditRun id to finalize.

    Returns:
        Result dict with merged ``report``, archive URLs, and metadata.
    """
    store = runtime._evidence_by_run.get(run_id)
    resolved_audit_run_id = str(audit_run_id or "").strip()
    if not resolved_audit_run_id and store is not None:
        meta = store.read_run_meta()
        resolved_audit_run_id = str(meta.get("audit_run_id") or "").strip()
    # Prefer on-disk framework reports (survive HITL / mid-run zips).
    disk_reports: dict[str, str] = {}
    if store is not None:
        for path in store.framework_report_paths():
            try:
                rel = path.parent.relative_to(store.root)
                key = str(rel).replace("\\", "/")
            except ValueError:
                key = path.parent.name
            disk_reports[key] = path.read_text(encoding="utf-8")

    full_sections = [
        "# Multi-host / multi-framework audit",
        "",
        "Sections: " + ", ".join(f"`{c[0]}`" for c in completed),
        "",
    ]
    ordered_reports: list[tuple[str, str, str]] = []
    if store is not None:
        full_sections.extend([f"Evidence directory: `{store.root}`", ""])
    for fw_id, title, report in completed:
        body = (disk_reports.get(fw_id) or report or "(empty report)").strip()
        if "## Audit archive" in body:
            body = body.split("## Audit archive", 1)[0].rstrip()
        ordered_reports.append((fw_id, title, body))
        full_sections.append(f"## `{fw_id}` — {title}")
        full_sections.append("")
        full_sections.append(body)
        full_sections.append("")
        full_sections.append("---")
        full_sections.append("")
    # Include any extra on-disk framework reports not listed in completed.
    known = {c[0] for c in completed}
    for fw_id, body in disk_reports.items():
        if fw_id in known:
            continue
        if "## Audit archive" in body:
            body = body.split("## Audit archive", 1)[0].rstrip()
        ordered_reports.append((fw_id, fw_id, body.strip()))
        full_sections.append(f"## `{fw_id}`")
        full_sections.append("")
        full_sections.append(body.strip())
        full_sections.append("")
        full_sections.append("---")
        full_sections.append("")
    status_counts: dict[str, int] = {
        "pass": 0,
        "fail": 0,
        "partial": 0,
        "error": 0,
        "skipped": 0,
        "other": 0,
    }
    ranked_rows: list[tuple[str, str, str, str, str]] = []
    all_finding_rows = []
    host_ids: set[str] = set()
    for fw_id, _title, body in ordered_reports:
        if "/" in fw_id:
            host_ids.add(fw_id.split("/", 1)[0].strip())
        for row in parse_report_findings(body):
            all_finding_rows.append(row)
            status = str(row.status or "").strip().lower()
            severity = str(row.severity or "Unknown").strip() or "Unknown"
            req_id = str(row.req_id or "").strip() or "REQ-???"
            title = str(row.title or "").strip() or "(untitled requirement)"
            if status in status_counts:
                status_counts[status] += 1
            elif status:
                status_counts["other"] += 1
            else:
                status_counts["error"] += 1
            ranked_rows.append((fw_id, req_id, title, severity, status or "error"))

    total = sum(status_counts.values())
    assessed = max(0, total - status_counts["skipped"])
    passed = status_counts["pass"]
    compliance_pct = (100.0 * passed / assessed) if assessed else 0.0
    audited_hosts = len(host_ids) if host_ids else (1 if ordered_reports else 0)

    sev_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 5,
    }
    status_rank = {"fail": 0, "error": 1, "partial": 2}
    top_findings = [row for row in ranked_rows if row[4] in {"fail", "error", "partial"}]
    top_findings.sort(
        key=lambda item: (
            sev_rank.get(item[3].lower(), 99),
            status_rank.get(item[4], 9),
            item[1],
            item[0],
        )
    )

    summary_sections = [
        "# Management summary",
        "",
        f"- Audited hosts: {audited_hosts}",
        f"- Requirements total: {total}",
        (
            "- Pass/Fail statistics: "
            f"pass={status_counts['pass']}, fail={status_counts['fail']}, "
            f"partial={status_counts['partial']}, error={status_counts['error']}, "
            f"skipped={status_counts['skipped']}, compliance={compliance_pct:.1f}%"
        ),
    ]
    try:
        summary_sections.append(
            format_chat_summary_visuals(
                all_finding_rows,
                status_counts=status_counts,
                compliance_pct=compliance_pct,
                hosts=audited_hosts,
                total=total,
            )
        )
    except Exception:  # noqa: BLE001
        pass
    summary_sections.extend(
        [
            "",
            "## Top 10 critical general findings",
            "",
        ]
    )
    if store is not None:
        summary_sections.extend([f"Evidence directory: `{store.root}`", ""])
    for fw_id, req_id, title, severity, status in top_findings[:10]:
        summary_sections.append(f"- [{severity}/{status}] `{req_id}` {title} (`{fw_id}`)")
    if not top_findings:
        summary_sections.append("- No critical/high non-pass findings detected.")
    combined_full = "\n".join(full_sections).strip() + "\n"
    chat_text = "\n".join(summary_sections).strip() + "\n"
    archive_path = ""
    archive_url = ""
    if store is not None:
        store.write_root_report(combined_full)
        if runtime.settings.archive_enabled:
            try:
                packaged = await package_and_publish_archive(store.root, runtime.settings)
                archive_path = str(packaged.get("zip_path") or "")
                archive_url = str(packaged.get("download_url") or "")
                chat_text = f"{chat_text.rstrip()}\n{packaged.get('chat_section') or ''}"
            except Exception as exc:  # noqa: BLE001
                chat_text = (
                    f"{chat_text.rstrip()}\n\n---\n\n"
                    f"(Archive packaging failed: {type(exc).__name__}: {exc})\n"
                )
    chat_text = f"{chat_text.rstrip()}{followup_footer()}"
    audit_run_status = ""
    if resolved_audit_run_id:
        registry = get_audit_registry(runtime.settings.evidence_dir)
        finalized = registry.finalize_run(resolved_audit_run_id)
        audit_run_status = finalized.status.value
        if store is not None:
            store.write_run_meta(
                audit_run_id=resolved_audit_run_id,
                audit_run_status=audit_run_status,
                status=audit_run_status,
            )
    return {
        "report": chat_text,
        "messages": [AIMessage(content=chat_text)],
        "framework_id": ",".join(c[0] for c in completed),
        "evidence_run_id": run_id,
        "audit_run_id": resolved_audit_run_id,
        "audit_run_status": audit_run_status,
        "evidence_run_dir": str(store.root) if store else "",
        "archive_path": archive_path,
        "archive_url": archive_url,
        "thread_id": base_thread,
        "awaiting_hitl": False,
        "findings": {},
    }


async def continue_multi_after_resume(
    runtime: AuditRuntime,
    thread_id: str,
    finished: dict[str, Any],
) -> dict[str, Any]:
    """Advance a multi-framework queue after one graph thread finishes.

    Pops session state for ``thread_id``, records the completed report,
    surfaces any sibling HITL pauses, then schedules remaining jobs.

    Args:
        thread_id: LangGraph thread that just completed or paused.
        finished: Result dict from the completed invocation.

    Returns:
        Next job result, merged multi-report, or ``finished`` unchanged.
    """
    session = runtime._forget_multi_session(thread_id)
    if not session:
        return finished

    completed: list[tuple[str, str, str]] = list(session.get("completed") or [])
    job_key = session.get("job_key") or session.get("framework_id") or ""
    fw_title = session.get("framework_title") or job_key
    host_id = session.get("evidence_host_id") or ""
    title = f"{host_id} — {fw_title}" if host_id else fw_title
    completed.append((job_key, title, finished.get("report") or ""))

    remaining_jobs: list[dict[str, Any]] = list(session.get("remaining_jobs") or [])
    remaining: list[str] = list(session.get("remaining") or [])
    user_text = session.get("user_text") or ""
    run_id = session.get("run_id") or finished.get("evidence_run_id")
    base_thread = session.get("base_thread") or thread_id.split(":")[0]
    plan_md = session.get("plan_md") or ""
    intake_state = session.get("intake_state")
    if not isinstance(intake_state, dict):
        intake_state = {}
    else:
        intake_state = dict(intake_state)
    audit_run_id = str(
        session.get("audit_run_id")
        or intake_state.get("audit_run_id")
        or finished.get("audit_run_id")
        or ""
    )
    if audit_run_id:
        intake_state["audit_run_id"] = audit_run_id
    job_id = str(session.get("job_id") or "")
    if audit_run_id and job_id and not finished.get("awaiting_hitl"):
        registry = get_audit_registry(runtime.settings.evidence_dir)
        active = registry.get_job(job_id)
        if active is not None and active.status == AuditJobStatus.RUNNING:
            if finished.get("error"):
                registry.fail_job(
                    job_id,
                    JobErrorInfo(
                        error_type="AuditError",
                        message=str(finished.get("error")),
                    ),
                )
            else:
                registry.complete_job(job_id)

    # Surface other HITL-paused siblings before starting new work.
    paused_siblings = [
        s
        for s in list(session.get("paused_siblings") or [])
        if isinstance(s, dict) and str(s.get("thread_id") or "") in runtime._multi_sessions
    ]
    if paused_siblings:
        for sib in paused_siblings:
            sib_tid = str(sib.get("thread_id") or "")
            sib_sess = runtime._multi_sessions.get(sib_tid)
            if not sib_sess:
                continue
            others = [s for s in paused_siblings if str(s.get("thread_id") or "") != sib_tid]
            sib_sess = dict(sib_sess)
            sib_sess["completed"] = list(completed)
            sib_sess["remaining_jobs"] = list(remaining_jobs)
            sib_sess["remaining"] = [str(j.get("framework_id") or "") for j in remaining_jobs]
            sib_sess["paused_siblings"] = others
            runtime._remember_multi_session(sib_tid, sib_sess)

        nxt = paused_siblings[0]
        nxt_tid = str(nxt.get("thread_id") or "")
        nxt_key = str(nxt.get("job_key") or nxt.get("framework_id") or "")
        sib_sess = runtime._multi_sessions.get(nxt_tid) or {}
        body = str(sib_sess.get("hitl_report") or "")
        if not body:
            body = f"Continue human review for `{nxt_key}` (thread `{nxt_tid}`)."
        prefix = runtime._multi_progress_preamble(
            completed,
            nxt_key,
            in_flight_keys=[str(s.get("job_key") or "") for s in paused_siblings[1:]],
            queued_keys=[_job_dict_key(j) for j in remaining_jobs],
        )
        preamble = f"{plan_md}\n{prefix}" if plan_md else prefix
        report = f"{preamble}{body}" if preamble else body
        return {
            "report": report,
            "awaiting_hitl": True,
            "thread_id": nxt_tid,
            "evidence_run_id": str(run_id or ""),
            "audit_run_id": audit_run_id,
            "messages": [AIMessage(content=report)],
        }

    if remaining_jobs:
        return await runtime._schedule_framework_jobs(
            user_text=str(user_text),
            base_thread=str(base_thread),
            run_id=str(run_id or ""),
            intake_state=intake_state,
            pending_jobs=remaining_jobs,
            completed=completed,
            plan_md=str(plan_md or ""),
        )

    if remaining:
        # Legacy remaining framework ids (no host) → serialize and schedule.
        legacy_jobs: list[dict[str, Any]] = []
        for fw_id in remaining:
            fw = get_framework(str(fw_id), runtime.settings.agents_dir)
            legacy_jobs.append(
                {
                    "framework_id": str(fw_id),
                    "framework_title": fw.title if fw else str(fw_id),
                    "evidence_host_id": "",
                    "inventory_target_ref": "",
                    "client_slug": str(intake_state.get("client_slug") or ""),
                    "ssh_host": "",
                    "ssh_port": "",
                    "ssh_user": "",
                    "ssh_strict": "",
                    "ssh_label": "",
                }
            )
        return await runtime._schedule_framework_jobs(
            user_text=str(user_text),
            base_thread=str(base_thread),
            run_id=str(run_id or ""),
            intake_state=intake_state,
            pending_jobs=legacy_jobs,
            completed=completed,
            plan_md=str(plan_md or ""),
        )

    merged = await runtime._merge_multi_reports(
        completed,
        run_id=str(run_id or ""),
        base_thread=base_thread,
        audit_run_id=audit_run_id or None,
    )
    return merged


async def start_frameworks_after_intake(
    runtime: AuditRuntime,
    *,
    user_text: str,
    base_thread: str,
    run_id: str,
    intake: dict[str, Any],
) -> dict[str, Any]:
    """Start framework jobs from confirmed intake ``selected_jobs`` (INPUT-001).

    Builds a typed :class:`~auditor.domain.AuditRequest`, persists it on the
    evidence run and AuditRun scope, then schedules host/framework jobs without
    NLP routing or inventory auto-discovery fallbacks.
    """
    selected_rows = list(intake.get("selected_jobs") or [])
    client_id = str(intake.get("client_id") or "").strip()
    client_slug_val = str(intake.get("client_slug") or "").strip()
    audit_run_id = str(intake.get("audit_run_id") or "").strip()

    if selected_rows and client_id and client_slug_val:
        try:
            clear_active_intake_pause(runtime.settings.evidence_dir)
        except OSError:
            pass

    if not selected_rows or not client_id or not client_slug_val:
        raise AuditRequestRejected(
            issues=[
                AuditRequestIssue(
                    location="intake",
                    code="missing_confirmed_scope",
                    message=(
                        "confirmed selected_jobs, client_id, and client_slug "
                        "are required before starting production audit jobs"
                    ),
                )
            ],
        )

    store = runtime._evidence_by_run.get(run_id)
    if store is None:
        store = EvidenceStore(runtime.settings.evidence_dir, run_id=run_id)
        runtime._evidence_by_run[run_id] = store

    preferred_lang = detect_report_language(user_text).code
    registry = get_audit_registry(runtime.settings.evidence_dir)

    try:
        request = build_audit_request_from_selected_jobs(
            client_id=client_id,
            client_slug=client_slug_val,
            selected_jobs=selected_rows,
            settings=runtime.settings,
            report_language=preferred_lang,
        )

        jobs = runtime._jobs_from_selected_intake(
            intake=intake, store=store, selected_rows=selected_rows
        )
        if not jobs:
            raise AuditRequestRejected(
                issues=[
                    AuditRequestIssue(
                        location="targets",
                        code="empty_framework_scope",
                        message="no runnable jobs could be built from confirmed selected_jobs",
                    )
                ],
            )

        # Persist secret-free request only after structural+semantic validation
        # and after runnable jobs are confirmed — before warehouse session / graphs.
        store.write_run_meta(
            input_contract_version=1,
            audit_request=persistable_audit_request(request),
            intake_complete=True,
            intake=intake,
            client_name=intake.get("client_name"),
            client_id=client_id,
            client_slug=client_slug_val,
            audit_types=str(intake.get("audit_types") or "both"),
            host_driven=True,
        )

        if audit_run_id:
            arun = registry.get_run(audit_run_id)
            if arun is not None:
                arun.scope = scope_with_audit_request(arun.scope, request)
                registry.save_run(arun)

        evidence_run = store.run_id or run_id
        session_info = None
        if audit_run_id:
            session_info = await start_session_safe(
                runtime.settings,
                client_name=str(intake.get("client_name") or ""),
                evidence_run_id=evidence_run,
                continue_thread_id=base_thread,
                evidence_path=str(store.root),
                audit_run_id=audit_run_id,
                client_id=client_id,
            )
        if session_info is not None:
            store.write_run_meta(
                results_session_number=session_info.session_number,
                results_session_id=session_info.id,
                audit_run_id=audit_run_id,
                client_id=client_id,
                status="running",
            )

        intake_state = {
            "intake_complete": True,
            "intake": intake,
            "client_name": str(intake.get("client_name") or ""),
            "client_id": client_id,
            "client_slug": client_slug_val,
            "audit_run_id": audit_run_id,
            "has_cmdb": bool(intake.get("has_cmdb")),
            "has_access": bool(intake.get("has_access")),
            "audit_types": str(intake.get("audit_types") or "both"),
            "audit_request": persistable_audit_request(request),
        }
        if session_info is not None:
            intake_state["results_session_number"] = session_info.session_number

        plan_md = runtime._format_host_framework_plan(jobs)
        store.write_run_meta(
            frameworks=[f"{t.slug}/{fw.id}" for t, _f, fw in jobs],
            host_plan=plan_md,
        )
        return await runtime._run_framework_jobs(
            user_text=user_text,
            base_thread=base_thread,
            run_id=run_id,
            intake_state=intake_state,
            jobs=jobs,
            plan_md=plan_md,
        )
    except AuditRequestRejected:
        if audit_run_id:
            try:
                registry.transition_run(audit_run_id, AuditRunStatus.FAILED)
                store.write_run_meta(audit_run_id=audit_run_id, status="failed")
            except Exception:  # noqa: BLE001
                pass
        raise


def multi_progress_preamble(
    runtime: AuditRuntime,
    completed: list[tuple[str, str, str]],
    current_id: str,
    *,
    in_flight_keys: list[str] | None = None,
    queued_keys: list[str] | None = None,
) -> str:
    """Build a short markdown header for multi-framework HITL pauses.

    Args:
        completed: ``(job_key, title, report)`` tuples finished so far.
        current_id: Job key currently waiting on operator input.
        in_flight_keys: Other paused / in-flight job keys.
        queued_keys: Not-yet-started job keys.

    Returns:
        Preamble string (may be empty when there is nothing useful to show).
    """
    if not completed and not in_flight_keys and not queued_keys:
        return ""
    lines = [
        "# Multi-framework audit (in progress)",
        "",
    ]
    if completed:
        lines.append("Completed before pause: " + ", ".join(f"`{c[0]}`" for c in completed))
    lines.append(f"Now waiting on: `{current_id}`")
    if in_flight_keys:
        lines.append("Also paused / in flight: " + ", ".join(f"`{k}`" for k in in_flight_keys if k))
    if queued_keys:
        lines.append("Queued: " + ", ".join(f"`{k}`" for k in queued_keys if k))
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _host_lock_key_from_target(target: InventorySshTarget | None) -> str:
    """Return same-host lock key for an inventory SSH target."""
    if target is None:
        return "_none_"
    return target.slug or target.host or "_none_"


def _host_lock_key_from_job(job: dict[str, Any]) -> str:
    """Return same-host lock key for a serialized job dict."""
    host = str(job.get("evidence_host_id") or "").strip()
    return host or "_none_"


def _serialize_host_job(
    target: InventorySshTarget | None,
    fw: Any,
    *,
    client_slug: str = "",
) -> dict[str, Any]:
    """Serialize one (host, framework) job for multi-session persistence."""
    inv_ref = ""
    if target is not None:
        # Prefer stable host identity over generic table labels (e.g. "SSH").
        inv_ref = (
            str(getattr(target, "slug", "") or "").strip()
            or str(getattr(target, "host", "") or "").strip()
            or str(getattr(target, "inventory_key", "") or "").strip()
            or str(getattr(target, "label", "") or "").strip()
        )
    return {
        "framework_id": fw.id,
        "framework_title": fw.title,
        "framework_version": str(getattr(fw, "version", "") or ""),
        "evidence_host_id": target.slug if target else "",
        "inventory_target_ref": inv_ref,
        "client_slug": client_slug,
        "ssh_host": target.host if target else "",
        "ssh_port": target.port if target else "",
        "ssh_user": target.user if target else "",
        "ssh_strict": target.strict_host_key if target else "",
        "ssh_label": target.label if target else "",
        "asset_id": str(getattr(target, "asset_id", "") or "") if target else "",
        "transport": target.transport if target else "ssh",
        "winrm_transport": target.winrm_transport if target else "",
        "winrm_use_ssl": target.winrm_use_ssl if target else "",
        "winrm_verify_ssl": target.winrm_verify_ssl if target else "",
    }


def _job_dict_key(job: dict[str, Any]) -> str:
    """Stable key for a serialized host/framework job."""
    host = str(job.get("evidence_host_id") or "").strip()
    fw = str(job.get("framework_id") or "")
    return f"{host}/{fw}" if host else fw


def _job_dict_thread_id(base_thread: str, job: dict[str, Any]) -> str:
    """Derive LangGraph thread id for a serialized job."""
    host = str(job.get("evidence_host_id") or "").strip()
    fw = str(job.get("framework_id") or "")
    return f"{base_thread}:{host}:{fw}" if host else f"{base_thread}:{fw}"


def _target_from_job_dict(
    job: dict[str, Any],
    settings: Settings | None = None,
) -> InventorySshTarget | None:
    """Rebuild ``InventorySshTarget`` from a serialized multi-session job."""
    slug = str(job.get("client_slug") or "").strip()
    inv_ref = str(job.get("inventory_target_ref") or "").strip()
    if settings is not None and slug and inv_ref:
        resolved = resolve_inventory_target(
            settings,
            client_slug=slug,
            inventory_target_ref=inv_ref,
        )
        if resolved is not None:
            return resolved
    host = str(job.get("ssh_host") or "").strip()
    if not host:
        return None
    return InventorySshTarget(
        host=host,
        port=str(job.get("ssh_port") or "22"),
        user=str(job.get("ssh_user") or ""),
        password="",
        private_key_path="",
        strict_host_key=str(job.get("ssh_strict") or ""),
        label=str(job.get("ssh_label") or ""),
        transport=str(job.get("transport") or "ssh"),
        winrm_transport=str(job.get("winrm_transport") or "ntlm"),
        winrm_use_ssl=str(job.get("winrm_use_ssl") or ""),
        winrm_verify_ssl=str(job.get("winrm_verify_ssl") or ""),
    )


def _job_display_title(job: dict[str, Any]) -> str:
    """Human-readable title for progress / merge sections."""
    host = str(job.get("ssh_host") or job.get("evidence_host_id") or "").strip()
    title = str(job.get("framework_title") or job.get("framework_id") or "")
    return f"{host} — {title}" if host else title


def jobs_from_selected_intake(
    runtime: AuditRuntime,
    *,
    intake: dict[str, Any],
    store: EvidenceStore,
    selected_rows: list[dict[str, Any]],
) -> list[tuple[InventorySshTarget, HostFacts, Any]]:
    """Rebuild (target, facts, framework) jobs from intake selected_jobs.

    Prefers host_facts.json written during stage-3 discovery so SSH is not
    repeated. Falls back to empty facts when the artifact is missing.
    """
    slug = str(intake.get("client_slug") or client_slug(str(intake.get("client_name") or "")))
    targets = list_client_ssh_targets(runtime.settings.inventory_dir, slug)
    if not targets and runtime.settings.ssh_host:
        targets = [
            InventorySshTarget(
                host=runtime.settings.ssh_host,
                port=str(runtime.settings.ssh_port or 22),
                user=runtime.settings.ssh_user or "",
                password=runtime.settings.ssh_password or "",
                private_key_path=runtime.settings.ssh_private_key_path or "",
            )
        ]
    by_slug = {t.slug: t for t in targets}
    by_host = {t.host: t for t in targets}
    jobs: list[tuple[InventorySshTarget, HostFacts, Any]] = []
    for row in selected_rows:
        host_id = str(row.get("host_id") or "").strip()
        ssh_host = str(row.get("ssh_host") or "").strip()
        target = by_slug.get(host_id) or by_host.get(ssh_host)
        if target is None:
            continue
        facts_path = store.host_root(target.slug) / "host_facts.json"
        facts = HostFacts(ssh_host=target.host)
        if facts_path.is_file():
            try:
                payload = json.loads(facts_path.read_text(encoding="utf-8"))
                facts = parse_host_facts_json(
                    payload.get("facts") or {},
                    ssh_host=target.host,
                )
            except Exception:  # noqa: BLE001
                facts = HostFacts(ssh_host=target.host)
        for fw_id in filter_scope_framework_ids([str(x) for x in (row.get("frameworks") or [])]):
            fw = get_framework(str(fw_id), runtime.settings.agents_dir)
            if fw is not None:
                jobs.append((target, facts, fw))
    return jobs


def format_host_framework_plan(
    runtime: AuditRuntime,
    jobs: list[tuple[InventorySshTarget, HostFacts, Any]],
) -> str:
    """Build markdown summary of host → framework routing plan.

    Args:
        jobs: List of ``(ssh_target, host_facts, framework)`` tuples.

    Returns:
        Markdown section listing each host and assigned frameworks.
    """
    lines = [
        "## Host → framework selection",
        "",
    ]
    if not jobs:
        lines.append("_No hosts discovered — empty scope (typed AuditRequest required)._")
        return "\n".join(lines)
    by_host: dict[str, list[str]] = {}
    labels: dict[str, str] = {}
    for target, facts, fw in jobs:
        key = target.slug
        labels[key] = f"`{target.host}` ({facts.hostname or '—'}, {facts.os_id or 'os?'})"
        by_host.setdefault(key, []).append(fw.id)
    for key, fws in by_host.items():
        lines.append(f"- {labels[key]} → {', '.join(f'`{x}`' for x in fws)}")
    lines.append("")
    return "\n".join(lines)


def remember_multi_session(runtime: AuditRuntime, thread_id: str, session: dict[str, Any]) -> None:
    """Store multi-framework orchestration state in memory and on disk.

    Args:
        thread_id: LangGraph checkpoint thread id for the active job.
        session: Remaining jobs, completed reports, intake state, etc.
    """
    runtime._multi_sessions[thread_id] = session
    run_id = str(session.get("run_id") or "")
    if run_id:
        try:
            save_multi_session(runtime.settings.evidence_dir, run_id, thread_id, session)
        except OSError:
            pass


def forget_multi_session(runtime: AuditRuntime, thread_id: str) -> dict[str, Any] | None:
    """Remove multi-session state for ``thread_id`` and delete disk copy.

    Args:
        thread_id: Thread whose session record should be dropped.

    Returns:
        The removed session dict, or ``None`` if not tracked.
    """
    session = runtime._multi_sessions.pop(thread_id, None)
    if session is None:
        return None
    run_id = str(session.get("run_id") or "")
    if run_id:
        try:
            drop_multi_session(runtime.settings.evidence_dir, run_id, thread_id)
        except OSError:
            pass
    return session


def reload_multi_sessions(runtime: AuditRuntime, run_id: str) -> None:
    """Load persisted multi-session records for ``run_id`` into memory.

    Args:
        run_id: Evidence run id shared across parallel framework threads.
    """
    if not run_id:
        return
    try:
        loaded = load_all_multi_sessions(runtime.settings.evidence_dir, run_id)
    except OSError:
        return
    for tid, sess in loaded.items():
        if tid not in runtime._multi_sessions:
            runtime._multi_sessions[tid] = sess


async def arun_request(
    runtime: AuditRuntime,
    request: AuditRequest,
    *,
    thread_id: str | None = None,
    operator_context: str = "",
) -> dict[str, Any]:
    """Run a production audit from a validated typed :class:`AuditRequest`."""
    validated = validate_audit_request_semantics(request, runtime.settings)
    run_id = new_run_id()
    base_thread = thread_id or f"audit-{uuid.uuid4().hex[:12]}"
    shared = EvidenceStore(runtime.settings.evidence_dir, run_id=run_id)
    runtime._evidence_by_run[run_id] = shared

    client = get_client_registry(runtime.settings.evidence_dir).get(validated.client_id)
    client_slug_val = client.slug if client is not None else validated.client_id

    shared.write_run_meta(
        input_contract_version=1,
        audit_request=persistable_audit_request(validated),
        user_request=truncate_text(
            operator_context,
            runtime.settings.max_user_request_chars,
            "user_request",
        ),
        thread_id=base_thread,
        client_id=validated.client_id,
        client_slug=client_slug_val,
    )

    intake_state: dict[str, Any] = {
        "client_id": validated.client_id,
        "client_slug": client_slug_val,
        "audit_request": persistable_audit_request(validated),
        "audit_types": "both",
        "has_access": True,
    }

    jobs: list[tuple[InventorySshTarget, HostFacts, Any]] = []
    for target in validated.targets:
        inv_target = resolve_inventory_target(
            runtime.settings,
            client_slug=client_slug_val,
            inventory_target_ref=target.inventory_target_ref,
        )
        if inv_target is None:
            continue
        facts = HostFacts(ssh_host=inv_target.host)
        for fw_ref in target.frameworks:
            fw = get_framework(fw_ref.framework_id, runtime.settings.agents_dir)
            if fw is not None:
                jobs.append((inv_target, facts, fw))

    if not jobs:
        raise AuditRequestRejected(
            issues=[
                AuditRequestIssue(
                    location="targets",
                    code="empty_framework_scope",
                    message="no runnable jobs could be built from AuditRequest targets",
                )
            ],
        )

    plan_md = runtime._format_host_framework_plan(jobs)
    shared.write_run_meta(
        frameworks=[f"{t.slug}/{fw.id}" for t, _f, fw in jobs],
        host_driven=True,
        host_plan=plan_md,
    )
    return await runtime._run_framework_jobs(
        user_text=operator_context,
        base_thread=base_thread,
        run_id=run_id,
        intake_state=intake_state,
        jobs=jobs,
        plan_md=plan_md,
    )


async def arun(
    runtime: AuditRuntime,
    user_text: str,
    *,
    thread_id: str | None = None,
) -> dict[str, Any]:
    """Run audit(s) for the request.

    When intake is enabled, asks client/access/audit-type first, then
    runs one or more framework graphs. Multiple frameworks run as separate
    graphs (sequential when HITL is on).
    """
    run_id = new_run_id()
    base_thread = thread_id or f"audit-{uuid.uuid4().hex[:12]}"
    shared = EvidenceStore(runtime.settings.evidence_dir, run_id=run_id)
    runtime._evidence_by_run[run_id] = shared
    shared.write_run_meta(
        user_request=truncate_text(
            user_text,
            runtime.settings.max_user_request_chars,
            "user_request",
        ),
        thread_id=base_thread,
    )

    if runtime.settings.intake_enabled:
        intake_tid = f"{base_thread}:intake"
        runtime._remember_multi_session(
            intake_tid,
            {
                "base_thread": base_thread,
                "run_id": run_id,
                "user_text": user_text,
            },
        )
        intake_result = await runtime.arun_intake(
            user_text,
            run_id=run_id,
            thread_id=intake_tid,
            store=shared,
        )
        if intake_result.get("awaiting_hitl") or intake_result.get("awaiting_intake"):
            return intake_result
        # Intake finished in one shot (rare without interrupts)
        snap = await runtime.intake_graph.aget_state({"configurable": {"thread_id": intake_tid}})
        intake = (snap.values or {}).get("intake") or {}
        if not isinstance(intake, dict):
            intake = {}
        # Prefer intake blob from the graph result when state is sparse.
        result_intake = intake_result.get("intake")
        if isinstance(result_intake, dict):
            merged = dict(result_intake)
            merged.update({k: v for k, v in intake.items() if v not in (None, "", [], {})})
            intake = merged
        runtime._forget_multi_session(intake_tid)
        if not list(intake.get("selected_jobs") or []):
            from langchain_core.messages import AIMessage

            msg = (
                "Pre-audit finished host discovery, but the host→framework plan "
                "was not confirmed. Reply **confirm** in this chat to start the audit, "
                "or describe what to exclude."
            )
            # Keep intake pause marker so the next turn resumes the same thread.
            from auditor.intake import format_intake_assistant_message

            report = format_intake_assistant_message(msg, intake_tid)
            return {
                "report": report,
                "messages": [AIMessage(content=report, name="auditor")],
                "awaiting_hitl": True,
                "awaiting_intake": True,
                "intake_complete": False,
                "thread_id": intake_tid,
                "evidence_run_id": str(intake.get("artifacts_run_id") or shared.run_id or run_id),
            }
        try:
            return await runtime._start_frameworks_after_intake(
                user_text=user_text,
                base_thread=base_thread,
                run_id=str(intake.get("artifacts_run_id") or run_id),
                intake=intake,
            )
        except AuditRequestRejected as exc:
            from langchain_core.messages import AIMessage

            msg = exc.operator_message()
            return {
                "report": msg,
                "messages": [AIMessage(content=msg, name="auditor")],
                "awaiting_hitl": False,
                "awaiting_intake": False,
                "error": exc.code,
            }

    raise AuditRequestRejected(
        issues=[
            AuditRequestIssue(
                location="request",
                code="typed_request_required",
                message=(
                    "Production audits require a typed AuditRequest; "
                    "call arun_request() instead of free-text arun()."
                ),
            )
        ],
    )


# Public aliases for façade wrappers / callers
host_lock_key_from_target = _host_lock_key_from_target
host_lock_key_from_job = _host_lock_key_from_job
serialize_host_job = _serialize_host_job
job_dict_key = _job_dict_key
job_dict_thread_id = _job_dict_thread_id
target_from_job_dict = _target_from_job_dict
job_display_title = _job_display_title

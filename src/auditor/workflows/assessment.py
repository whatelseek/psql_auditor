"""Requirement assessment, evidence gathering, and reconnect."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
)
from langgraph.graph.message import REMOVE_ALL_MESSAGES

from auditor.checklist import Requirement
from auditor.context import count_tool_rounds, truncate_text
from auditor.domain.assessment_result import AssessmentError, AssessmentResult, ResultIdentity
from auditor.domain.result_identity import index_by_result_id, requirement_ids_in
from auditor.evidence_store import EvidenceStore
from auditor.frameworks import get_framework
from auditor.language import ReportLanguage, language_instruction
from auditor.progress import emit_phase, emit_req_status
from auditor.prompts import (
    EVIDENCE_FORCE_PROMPT,
    EVIDENCE_PROMPT,
    EVIDENCE_SYSTEM_PROMPT,
    FILL_CELL_PROMPT,
    FILL_SYSTEM_PROMPT,
)
from auditor.result_identity_bind import attach_result_identity, require_persistable
from auditor.results_store import (
    record_requirement_result_safe,
    snapshot_checklist_safe,
    sync_session_status_from_run_meta,
)
from auditor.session_store import write_run_status
from auditor.state import AuditorState, Finding
from auditor.tools.mcp_client import reconnect_mcp_session
from auditor.workflows.helpers import (
    _extract_json,
    _is_recoverable_finding,
)
from auditor.workflows.protocols import AuditRuntime


def _framework_version_for(runtime: AuditRuntime, state: AuditorState, framework_id: str) -> str:
    """Resolve mandatory framework_version from state or agent frontmatter."""
    ver = str(state.get("framework_version") or "").strip()
    if ver:
        return ver
    bare = framework_id.split("/", 1)[-1] if framework_id else ""
    fw = get_framework(bare, runtime.settings.agents_dir) if bare else None
    return str(getattr(fw, "version", "") or "").strip()


def _bind_finding(
    runtime: AuditRuntime,
    state: AuditorState,
    finding: Finding | AssessmentResult,
    *,
    framework_id: str,
    store: EvidenceStore | None,
) -> AssessmentResult:
    """Attach canonical identity; validate fully when persisting to disk/DB."""
    ver = _framework_version_for(runtime, state, framework_id)
    existing = None
    if store is not None:
        existing = store.load_finding(framework_id, finding.requirement_id)
    bound = attach_result_identity(
        finding,
        state=state,
        framework_id=framework_id,
        framework_version=ver,
        existing=existing,
    )
    if store is not None:
        return require_persistable(bound)
    return bound


async def assess_parallel(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
    """Node: fill report cells for pending requirements (parallel)."""
    requirements = state.get("requirements") or {}
    pending = list(state.get("pending_ids") or [])
    if not pending:
        return {
            "pending_ids": [],
            "messages": [AIMessage(content="No pending requirements to assess.", name="auditor")],
        }

    user_request = state.get("user_request") or "(none)"
    framework_id = state.get("framework_id") or ""
    report_lang = runtime._report_language(state, user_request)
    store = runtime._store_from_state(state)
    host_id = str(state.get("evidence_host_id") or "").strip()
    if store is not None and host_id:
        store.host_segment = host_id
    limit = max(1, runtime.settings.max_parallel_assessments)
    sem = asyncio.Semaphore(limit)
    thread_hint = str(state.get("thread_id") or "")
    emit_phase(
        f"Assessing {len(pending)} requirement(s) for `{framework_id}` (concurrency={limit})…",
        framework_id=framework_id,
    )
    if requirements:
        evidence_rel = ""
        hostname = None
        ssh_host = None
        if store is not None:
            try:
                evidence_rel = str(
                    store.root.relative_to(Path(runtime.settings.evidence_dir).resolve())
                )
            except ValueError:
                evidence_rel = str(store.root)
            facts_path = store.host_root(host_id) / "host_facts.json" if host_id else None
            if facts_path is None:
                facts_path = store.root / "host_facts.json"
            if facts_path.is_file():
                try:
                    import json as _json

                    raw_facts = _json.loads(facts_path.read_text(encoding="utf-8"))
                    hostname = str(raw_facts.get("hostname") or "") or None
                    ssh_host = str(raw_facts.get("ssh_host") or "") or None
                except Exception:  # noqa: BLE001
                    pass
        await snapshot_checklist_safe(
            runtime.settings,
            client_name=str(state.get("client_name") or "") or (store.run_id if store else ""),
            evidence_run_id=str(state.get("evidence_run_id") or (store.run_id if store else "")),
            framework_id=framework_id or "framework",
            requirements=requirements,
            evidence_host_id=host_id or None,
            session_number=runtime._results_session_number(state, store),
            hostname=hostname,
            ssh_host=ssh_host or host_id or None,
            evidence_relpath=evidence_rel,
            audit_run_id=str(state.get("audit_run_id") or ""),
            client_id=str(state.get("client_id") or ""),
        )

    async def _worker(req_id: str) -> AssessmentResult:
        """Assess one requirement under the concurrency semaphore."""
        async with sem:
            req_title = requirements[req_id].title
            emit_req_status(
                req_id,
                "started",
                framework_id=framework_id,
                requirement_title=req_title,
                text=f"Assessing `{req_id}: {req_title}`…",
            )
            try:
                special: Any = runtime._deterministic_it_audit_finding(
                    req_id=req_id,
                    requirement=requirements[req_id],
                    framework_id=framework_id,
                    state=state,
                    store=store,
                )
                if special is not None:
                    special = _bind_finding(
                        runtime, state, special, framework_id=framework_id, store=store
                    )
                    if store is not None:
                        store.write_requirement(
                            framework_id,
                            req_id,
                            {
                                "id": requirements[req_id].id,
                                "title": requirements[req_id].title,
                                "category": requirements[req_id].category,
                                "severity": requirements[req_id].severity,
                                "how_to_verify": requirements[req_id].how_to_verify,
                                "pass_criteria": requirements[req_id].pass_criteria,
                            },
                        )
                        store.write_finding(framework_id, req_id, _finding_disk_payload(special))
                    await runtime._warehouse_live_upsert(
                        state,
                        framework_id=framework_id,
                        finding=special,
                        requirement=requirements.get(req_id),
                        store=store,
                    )
                    emit_req_status(
                        req_id,
                        special.status,
                        framework_id=framework_id,
                        requirement_title=req_title,
                    )
                    return special
                finding: Finding | AssessmentResult = await runtime._fill_requirement_cells(
                    req_id=req_id,
                    requirement=requirements[req_id],
                    user_request=user_request,
                    framework_id=framework_id,
                    store=store,
                    report_language=report_lang,
                    state=state,
                )
                finding = _bind_finding(
                    runtime, state, finding, framework_id=framework_id, store=store
                )
                if store is not None:
                    store.write_finding(framework_id, req_id, _finding_disk_payload(finding))
                await runtime._warehouse_live_upsert(
                    state,
                    framework_id=framework_id,
                    finding=finding,
                    requirement=requirements.get(req_id),
                    store=store,
                )
                emit_req_status(
                    req_id,
                    finding.status,
                    framework_id=framework_id,
                    requirement_title=req_title,
                )
                return finding
            except asyncio.CancelledError:
                if store is not None and thread_hint:
                    remaining = [
                        rid
                        for rid in pending
                        if rid not in requirement_ids_in(state.get("findings") or {})
                    ]
                    write_run_status(
                        runtime.settings.evidence_dir,
                        store.run_id,
                        status="interrupted",
                        thread_id=thread_hint,
                        pending_ids=remaining,
                        framework_id=framework_id,
                    )
                    await sync_session_status_from_run_meta(
                        runtime.settings,
                        run_id=store.run_id,
                        status="interrupted",
                        thread_id=thread_hint,
                        pending_ids=remaining,
                        framework_id=framework_id,
                    )
                raise
            except Exception as exc:  # noqa: BLE001
                from auditor.domain.result_identity import new_result_id

                req = requirements.get(req_id)
                bare_fw = framework_id.split("/", 1)[-1] if framework_id else ""
                finding = AssessmentResult.from_execution_error(
                    identity=ResultIdentity(
                        result_id=new_result_id(),
                        client_id="",
                        audit_run_id="",
                        asset_id="",
                        framework_id=bare_fw,
                        framework_version="",
                        requirement_id=req_id,
                    ),
                    exc=exc,
                    recommendation="Retry after restoring SSH/MCP session",
                    title=req.title if req else "",
                    severity=req.severity if req else "",
                    category=req.category if req else "",
                    pass_criteria=req.pass_criteria if req else "",
                )
                finding = _bind_finding(
                    runtime, state, finding, framework_id=framework_id, store=store
                )
                if store is not None:
                    store.write_finding(
                        framework_id,
                        req_id,
                        _finding_disk_payload(finding),
                    )
                await runtime._warehouse_live_upsert(
                    state,
                    framework_id=framework_id,
                    finding=finding,
                    requirement=req,
                    store=store,
                )
                emit_req_status(
                    req_id,
                    "error",
                    framework_id=framework_id,
                    requirement_title=req.title if req else "",
                    text=str(exc)[:200],
                )
                return finding

    work_ids = [rid for rid in pending if rid in requirements]
    # Finish as completed so disk findings survive mid-run cancel.
    tasks = {asyncio.create_task(_worker(rid)): rid for rid in work_ids}
    findings_list: list[AssessmentResult] = []
    try:
        for coro in asyncio.as_completed(tasks):
            findings_list.append(await coro)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if store is not None:
            done_ids = {f.requirement_id for f in findings_list}
            # Also pick up any findings already on disk from cancelled workers.
            for rid in work_ids:
                if rid in done_ids:
                    continue
                raw = store.load_finding(framework_id, rid)
                if raw:
                    done_ids.add(rid)
            remaining = [rid for rid in work_ids if rid not in done_ids]
            write_run_status(
                runtime.settings.evidence_dir,
                store.run_id,
                status="interrupted",
                thread_id=thread_hint,
                pending_ids=remaining,
                framework_id=framework_id,
            )
            await sync_session_status_from_run_meta(
                runtime.settings,
                run_id=store.run_id,
                status="interrupted",
                thread_id=thread_hint or "",
                pending_ids=remaining,
                framework_id=framework_id,
            )
        raise

    # Physical index is result_id; completion order must not change identities.
    new_findings = index_by_result_id(findings_list)

    # Keep recoverable failures in pending_ids for the reconnect cycle.
    retryable = [f.requirement_id for f in findings_list if _is_recoverable_finding(f)]
    return {
        "findings": new_findings,
        "pending_ids": retryable,
        "current_id": None,
        "messages": [
            RemoveMessage(id=REMOVE_ALL_MESSAGES),
            AIMessage(
                content=(
                    f"Assessed {len(new_findings)} rows for `{framework_id}` "
                    f"(concurrency={limit}); "
                    f"recoverable failures queued={len(retryable)}."
                ),
                name="auditor",
            ),
        ],
    }


async def reconnect_session(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
    """Node: restore MCP sessions and bump retry counter (graph cycle)."""
    status = await reconnect_mcp_session()
    retry_count = int(state.get("retry_count") or 0) + 1
    pending = state.get("pending_ids") or []
    return {
        "retry_count": retry_count,
        "messages": [
            AIMessage(
                content=(
                    f"Reconnect attempt #{retry_count}: {status}. "
                    f"Re-queueing {len(pending)} requirements."
                ),
                name="auditor",
            )
        ],
    }


async def fill_requirement_cells(
    runtime: AuditRuntime,
    req_id: str,
    requirement: Requirement,
    user_request: str,
    framework_id: str,
    store: EvidenceStore | None = None,
    report_language: ReportLanguage | None = None,
    *,
    ssh_only: bool = False,
    state: AuditorState | None = None,
) -> AssessmentResult:
    """Run evidence gathering + fill model for one requirement cell.

    Writes requirement metadata and finding JSON to the evidence store
    when ``store`` is provided.

    Args:
        req_id: Requirement id.
        requirement: Parsed checklist requirement.
        user_request: Original operator request (context).
        framework_id: Active framework id.
        store: Optional evidence store for disk artifacts.
        report_language: Language for fill prompts.
        ssh_only: When True, bind only SSH tools (host_facts discovery).

    Returns:
        Completed ``AssessmentResult`` for the requirement.
    """
    if store is not None:
        store.write_requirement(
            framework_id,
            req_id,
            {
                "id": requirement.id,
                "title": requirement.title,
                "category": requirement.category,
                "severity": requirement.severity,
                "how_to_verify": requirement.how_to_verify,
                "pass_criteria": requirement.pass_criteria,
            },
        )
    evidence = await runtime._gather_evidence(
        req_id,
        requirement,
        user_request,
        framework_id,
        store=store,
        ssh_only=ssh_only,
    )
    evidence = truncate_text(
        evidence,
        runtime.settings.max_tool_output_chars,
        "evidence",
    )
    report_lang = report_language or runtime._report_language_from_request(user_request)
    lang_instr = language_instruction(report_lang)
    fill_messages = [
        SystemMessage(content=FILL_SYSTEM_PROMPT.format(language_instruction=lang_instr)),
        HumanMessage(
            content=FILL_CELL_PROMPT.format(
                report_language=report_lang.name,
                language_instruction=lang_instr,
                req_id=req_id,
                title=requirement.title,
                category=requirement.category,
                severity=requirement.severity,
                pass_criteria=requirement.pass_criteria,
                how_to_verify=requirement.how_to_verify,
                evidence=evidence or "(no evidence collected)",
            )
        ),
    ]
    response = await runtime.fill_model.ainvoke(fill_messages)
    finding: Finding | AssessmentResult = runtime._cells_to_finding(
        req_id, requirement, response, evidence
    )
    if state is not None:
        finding = _bind_finding(runtime, state, finding, framework_id=framework_id, store=store)
    if store is not None:
        store.write_finding(framework_id, req_id, _finding_disk_payload(finding))
    if isinstance(finding, AssessmentResult):
        return finding
    return AssessmentResult.from_finding(finding)


async def gather_evidence(
    runtime: AuditRuntime,
    req_id: str,
    requirement: Requirement,
    user_request: str,
    framework_id: str,
    store: EvidenceStore | None = None,
    *,
    ssh_only: bool = False,
) -> str:
    """Tool-calling loop: gather raw evidence text for one requirement.

    Injects playbook memory, runs the evidence LLM with SSH/MCP tools,
    and concatenates tool outputs and final narrative.

    Args:
        req_id: Requirement id (for progress and playbook lookup).
        requirement: Checklist requirement being verified.
        user_request: Original operator request.
        framework_id: Active framework id.
        store: Optional evidence store for tool call logging.
        ssh_only: When True, bind only SSH tools.

    Returns:
        Combined evidence string for the fill model.
    """
    playbook_block = ""
    if runtime.playbooks is not None and runtime.settings.memory_enabled:
        playbook_block = runtime.playbooks.format_prompt_block(framework_id, req_id)
    if ssh_only:
        tool_note = "Use ONLY ssh_run / ssh_read_file for this inventory check."
    else:
        tool_note = "Use inventory plus SSH/Postgres MCP tools appropriate for this framework."
    messages: list = [
        SystemMessage(
            content=(f"{EVIDENCE_SYSTEM_PROMPT}\n\nActive framework: `{framework_id}`. {tool_note}")
        ),
        HumanMessage(
            content=EVIDENCE_PROMPT.format(
                user_request=user_request,
                requirement_block=requirement.to_prompt_block(),
                playbook_block=playbook_block or "(no playbook memory for this requirement)",
            )
        ),
    ]
    chunks: list[str] = []
    max_rounds = runtime.settings.max_tool_rounds_per_item
    evidence_llm = runtime.evidence_model_ssh if ssh_only else runtime._evidence_llm()

    for _ in range(max_rounds + 1):
        rounds = count_tool_rounds(messages)
        if rounds >= max_rounds:
            messages.append(HumanMessage(content=EVIDENCE_FORCE_PROMPT))
            response = await runtime.fill_model.ainvoke(messages)
            chunks.append(str(response.content or ""))
            break

        response = await evidence_llm.ainvoke(messages)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            chunks.append(str(response.content or ""))
            break

        tool_messages = await runtime._execute_tool_calls(
            tool_calls,
            framework_id=framework_id,
            req_id=req_id,
            requirement_title=requirement.title,
            store=store,
        )
        messages.extend(tool_messages)
        for tm in tool_messages:
            chunks.append(f"[{tm.name}] {tm.content}")

    return "\n---\n".join(c.strip() for c in chunks if c and c.strip())


def _finding_disk_payload(finding: Finding | AssessmentResult) -> dict:
    """Serialize assessment result for evidence disk (canonical field names)."""
    if isinstance(finding, AssessmentResult):
        return finding.to_persist_dict()
    return AssessmentResult.from_finding(finding).to_persist_dict()


def cells_to_finding(
    runtime: AuditRuntime,
    req_id: str,
    req: Requirement,
    ai: AIMessage,
    fallback_evidence: str,
    *,
    identity: ResultIdentity | None = None,
) -> AssessmentResult:
    """Parse fill-model JSON into a validated :class:`AssessmentResult` (CORE-004).

    Malformed model output yields a controlled ``status=error`` result with
    structured :class:`AssessmentError` — never a partially valid finding.
    Forces ``error`` when evidence looks like a transport failure even if the
    model returned pass/fail.

    Returns:
        Truncated ``AssessmentResult`` ready for state and disk.
    """
    from auditor.domain.result_identity import new_result_id

    raw_text = str(ai.content or "")
    data = _extract_json(raw_text)
    ident = identity or ResultIdentity(
        result_id=new_result_id(),
        client_id="",
        audit_run_id="",
        asset_id="",
        framework_id="",
        framework_version="",
        requirement_id=req_id,
    )
    if ident.requirement_id != req_id:
        ident = ident.model_copy(update={"requirement_id": req_id})
    result = AssessmentResult.from_llm_payload(
        data,
        identity=ident,
        title=req.title,
        severity=req.severity,
        category=req.category,
        pass_criteria=req.pass_criteria,
        fallback_observation=fallback_evidence or raw_text,
    )
    # Transport failures must stay status=error so reconnect / HITL can fire.
    probe = Finding(
        requirement_id=req_id,
        status="error",
        evidence=result.observation,
        notes=result.notes,
    )
    if result.status != "error" and _is_recoverable_finding(probe):
        result = result.with_correction(
            status="error",
            error=AssessmentError(
                error_type="TransportFailure",
                message="Recoverable transport failure detected in observation",
            ),
        )
    result = result.with_correction(
        observation=truncate_text(
            result.observation or "",
            runtime.settings.max_finding_evidence_chars,
            "observation",
        ),
        recommendation=truncate_text(
            result.recommendation or "",
            min(runtime.settings.max_finding_evidence_chars, 1200),
            "recommendation",
        ),
    )
    return result


def deterministic_it_audit_finding(
    runtime: AuditRuntime,
    *,
    req_id: str,
    requirement: Requirement,
    framework_id: str,
    state: AuditorState,
    store: EvidenceStore | None,
) -> Finding | None:
    """Resolve IT-audit REQs that should not HITL-loop.

    REQ-006: pass/fail on ``INVENTORY.md`` (never ``error``).
    REQ-007: summarize intake access probe (never call placeholder SSH).
    """
    if framework_id != "it_audit":
        return None

    intake = state.get("intake") or {}

    if req_id == "REQ-006":
        inv_path = store.root / "INVENTORY.md" if store is not None else None
        if inv_path is not None and inv_path.is_file():
            return Finding(
                requirement_id=req_id,
                title=requirement.title,
                status="pass",
                severity=requirement.severity,
                category=requirement.category,
                pass_criteria=requirement.pass_criteria,
                evidence=(f"Inventory-only assessment: INVENTORY.md is present at `{inv_path}`."),
                remediation="",
                notes="Deterministic inventory file check.",
            )
        return Finding(
            requirement_id=req_id,
            title=requirement.title,
            status="fail",
            severity=requirement.severity,
            category=requirement.category,
            pass_criteria=requirement.pass_criteria,
            evidence=(
                "Inventory-only assessment: INVENTORY.md is missing from "
                "the evidence run directory."
            ),
            remediation=(
                "Ensure intake wrote inventory/<client>/INVENTORY.md and "
                "copied it into the artifacts run folder."
            ),
            notes="Deterministic inventory file check.",
        )

    if req_id == "REQ-007":
        probe = intake.get("access_probe") or {}
        services = list(probe.get("services") or [])
        if not services:
            return Finding(
                requirement_id=req_id,
                title=requirement.title,
                status="fail",
                severity=requirement.severity,
                category=requirement.category,
                pass_criteria=requirement.pass_criteria,
                evidence="No intake access_probe results were stored.",
                remediation="Re-run intake with access=yes so SSH/PG are probed.",
            )
        lines = [
            f"- **{s.get('name')}**: `{s.get('status')}` — {s.get('detail') or '—'}"
            for s in services
        ]
        any_ok = bool(probe.get("any_ok"))
        return Finding(
            requirement_id=req_id,
            title=requirement.title,
            status="pass" if any_ok else "fail",
            severity=requirement.severity,
            category=requirement.category,
            pass_criteria=requirement.pass_criteria,
            evidence="Intake access probe summary:\n" + "\n".join(lines),
            remediation="" if any_ok else "Fix SSH/Postgres credentials in inventory and re-probe.",
            notes="Deterministic from intake access_probe.",
        )

    return None


def store_from_state(runtime: AuditRuntime, state: AuditorState) -> EvidenceStore | None:
    """Resolve the evidence store for this graph run (if configured)."""
    run_id = state.get("evidence_run_id") or ""
    run_dir = state.get("evidence_run_dir") or ""
    if not run_id and not run_dir:
        return None
    if not run_id and run_dir:
        run_id = Path(run_dir).name
    if run_id in runtime._evidence_by_run:
        return runtime._evidence_by_run[run_id]
    store = EvidenceStore(runtime.settings.evidence_dir, run_id=run_id)
    if run_dir:
        path = Path(run_dir)
        if path.is_dir():
            store.root = path
            store.run_id = path.name
    runtime._evidence_by_run[store.run_id] = store
    return store


async def warehouse_live_upsert(
    runtime: AuditRuntime,
    state: AuditorState,
    *,
    framework_id: str,
    finding: Finding | AssessmentResult,
    requirement: Requirement | None,
    store: EvidenceStore | None,
    source: str = "live",
) -> None:
    """Best-effort dual-write of one filled REQ to the results warehouse."""
    evidence_rel = ""
    hostname = None
    ssh_host = None
    host_id = str(state.get("evidence_host_id") or "").strip()
    if store is not None:
        try:
            evidence_rel = str(
                store.root.relative_to(Path(runtime.settings.evidence_dir).resolve())
            )
        except ValueError:
            evidence_rel = str(store.root)
        facts_path = (
            store.host_root(host_id) / "host_facts.json"
            if host_id
            else store.root / "host_facts.json"
        )
        if facts_path.is_file():
            try:
                import json as _json

                raw_facts = _json.loads(facts_path.read_text(encoding="utf-8"))
                hostname = str(raw_facts.get("hostname") or "") or None
                ssh_host = str(raw_facts.get("ssh_host") or "") or None
            except Exception:  # noqa: BLE001
                pass
    await record_requirement_result_safe(
        runtime.settings,
        client_name=str(state.get("client_name") or "") or (store.run_id if store else ""),
        evidence_run_id=str(state.get("evidence_run_id") or (store.run_id if store else "")),
        framework_id=framework_id or "framework",
        evidence_host_id=host_id or None,
        finding=finding,
        requirement=requirement,
        evidence_relpath=evidence_rel,
        source=source,
        session_number=runtime._results_session_number(state, store),
        hostname=hostname,
        ssh_host=ssh_host or host_id or None,
        audit_run_id=str(getattr(finding, "audit_run_id", "") or state.get("audit_run_id") or ""),
        client_id=str(getattr(finding, "client_id", "") or state.get("client_id") or ""),
    )


def results_session_number(
    runtime: AuditRuntime,
    state: AuditorState,
    store: EvidenceStore | None,
) -> int | None:
    """Resolve warehouse session number from state or disk meta."""
    if store is not None:
        raw = store.read_run_meta().get("results_session_number")
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    if state.get("results_session_number") is not None:
        try:
            return int(state["results_session_number"])
        except (TypeError, ValueError):
            return None
    return None

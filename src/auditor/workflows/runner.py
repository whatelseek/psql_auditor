"""Single-run lifecycle: arun_one, aresume, acontinue, intake invoke."""

from __future__ import annotations

import uuid
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Iterator

from langchain_core.messages import HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from auditor.context import truncate_text
from auditor.evidence_store import EvidenceStore, bind_host_segment, new_run_id
from auditor.frameworks import get_framework
from auditor.intake import client_slug
from auditor.language import detect_report_language
from auditor.progress import emit_phase
from auditor.runtime_target import bind_runtime_credentials
from auditor.secrets_file import InventorySshTarget, bind_host_target, read_client_credentials
from auditor.session_store import write_run_status
from auditor.state import AuditorState
from auditor.workflows.protocols import AuditRuntime

try:
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
except ImportError:  # pragma: no cover
    AsyncSqliteSaver = None  # type: ignore[misc, assignment]

async def arun_one(runtime: AuditRuntime,
    user_text: str,
    *,
    framework_id: str | None = None,
    run_id: str | None = None,
    thread_id: str | None = None,
    intake_state: dict[str, Any] | None = None,
    evidence_host_id: str | None = None,
    ssh_target: InventorySshTarget | None = None,
) -> dict[str, Any]:
    """Run a single-framework audit graph (optionally pinned)."""
    rid = run_id or new_run_id()
    tid = thread_id or f"audit-{uuid.uuid4().hex[:12]}"
    store = runtime._evidence_by_run.get(rid)
    if store is None:
        store = EvidenceStore(runtime.settings.evidence_dir, run_id=rid)
        runtime._evidence_by_run[store.run_id] = store
    if evidence_host_id:
        store.host_segment = evidence_host_id
    meta: dict[str, Any] = {
        "user_request": truncate_text(
            user_text,
            runtime.settings.max_user_request_chars,
            "user_request",
        ),
        "thread_id": tid,
    }
    if framework_id:
        meta["framework_id"] = framework_id
    if evidence_host_id:
        meta["evidence_host_id"] = evidence_host_id
    report_lang = detect_report_language(user_text)
    meta["report_language"] = report_lang.code
    if intake_state:
        meta["intake"] = intake_state.get("intake") or intake_state
        meta["client_name"] = intake_state.get("client_name")
        meta["audit_types"] = intake_state.get("audit_types")
        if intake_state.get("results_session_number") is not None:
            meta["results_session_number"] = intake_state[
                "results_session_number"
            ]
    store.write_run_meta(**meta)
    initial: AuditorState = {
        "messages": [HumanMessage(content=user_text)],
        "user_request": truncate_text(
            user_text,
            runtime.settings.max_user_request_chars,
            "user_request",
        ),
        "report_language": report_lang.code,
        "retry_count": 0,
        "evidence_run_id": store.run_id,
        "evidence_run_dir": str(store.root),
        "hitl_skipped": [],
        "awaiting_hitl": False,
        "intake_complete": True,
        "thread_id": tid,
    }
    if intake_state:
        initial.update(
            {
                "intake": dict(intake_state.get("intake") or intake_state),
                "client_name": str(intake_state.get("client_name") or ""),
                "has_cmdb": bool(intake_state.get("has_cmdb")),
                "has_access": bool(intake_state.get("has_access")),
                "audit_types": str(intake_state.get("audit_types") or ""),
            }
        )
        if intake_state.get("results_session_number") is not None:
            initial["results_session_number"] = int(
                intake_state["results_session_number"]
            )
    if framework_id:
        initial["framework_id"] = framework_id
    if evidence_host_id:
        initial["evidence_host_id"] = evidence_host_id
    config = {"configurable": {"thread_id": tid}}

    async def _invoke() -> dict[str, Any]:
        """Run the main graph and decorate with HITL/intake messaging."""
        result = await runtime.graph.ainvoke(initial, config)
        return runtime._decorate_result(result, thread_id=tid, store=store)

    intake_for_scope = (
        (intake_state.get("intake") if intake_state else None)
        or intake_state
        or {}
    )
    if not isinstance(intake_for_scope, dict):
        intake_for_scope = {}
    with runtime._target_scope(intake=intake_for_scope, ssh_target=ssh_target):
        with bind_host_segment(evidence_host_id):
            return await _invoke()

async def aresume(runtime: AuditRuntime, thread_id: str, user_text: str) -> dict[str, Any]:
    """Resume a graph paused on intake or ``human_gate``."""
    config = {"configurable": {"thread_id": thread_id}}
    is_intake = ":intake" in thread_id or thread_id.endswith("intake")
    graph = runtime.intake_graph if is_intake else runtime.graph
    try:
        pre = await graph.aget_state(config)
        pre_values = pre.values or {}
    except Exception:  # noqa: BLE001
        pre_values = {}
    slug = runtime._client_slug_from_values(pre_values)
    with runtime._target_scope(client_slug=slug, intake=pre_values.get("intake") if isinstance(pre_values.get("intake"), dict) else None):
        result = await graph.ainvoke(Command(resume=user_text), config)
    snap = await graph.aget_state(config)
    values = snap.values or {}
    run_id = values.get("evidence_run_id") or ""
    store = runtime._evidence_by_run.get(run_id)
    if store is None and values.get("evidence_run_dir"):
        store = EvidenceStore(
            runtime.settings.evidence_dir,
            run_id=run_id or Path(str(values["evidence_run_dir"])).name,
        )
        runtime._evidence_by_run[store.run_id] = store
    decorated = runtime._decorate_result(
        result, thread_id=thread_id, store=store, intake=is_intake
    )
    if decorated.get("awaiting_hitl"):
        return decorated

    if is_intake and values.get("intake_complete"):
        # Continue into framework audits using intake answers.
        session = runtime._forget_multi_session(thread_id) or {}
        user_req = session.get("user_text") or values.get("user_request") or user_text
        base_thread = session.get("base_thread") or thread_id.replace(":intake", "")
        run_id = (
            values.get("evidence_run_id")
            or session.get("run_id")
            or run_id
        )
        intake = values.get("intake") or {}
        return await runtime._start_frameworks_after_intake(
            user_text=str(user_req),
            base_thread=base_thread,
            run_id=str(run_id),
            intake=intake if isinstance(intake, dict) else {},
        )

    # If this thread was part of a multi-framework run, continue the queue.
    return await runtime._continue_multi_after_resume(thread_id, decorated)

async def acontinue(runtime: AuditRuntime, thread_id: str, *, run_id: str | None = None) -> dict[str, Any]:
    """Resume an interrupted mid-assess (or HITL) run after disconnect/restart."""
    emit_phase(f"Continuing audit from checkpoint (`{thread_id}`)…")
    config = {"configurable": {"thread_id": thread_id}}
    is_intake = ":intake" in thread_id or thread_id.endswith("intake")
    graph = runtime.intake_graph if is_intake else runtime.graph

    rid = run_id or ""
    if not rid:
        found = find_interrupted_run(runtime.settings.evidence_dir)
        if found:
            rid, meta = found
            if not thread_id:
                thread_id = str(meta.get("continue_thread_id") or thread_id)
        else:
            # Fall back to thread meta on any run folder
            rid = ""

    if rid:
        runtime._reload_multi_sessions(rid)
        store = runtime._evidence_by_run.get(rid)
        if store is None:
            try:
                store = EvidenceStore.open_existing(runtime.settings.evidence_dir, rid)
                runtime._evidence_by_run[rid] = store
            except Exception:  # noqa: BLE001
                store = None
    else:
        store = None

    # Prefer LangGraph checkpoint if the graph still has work / interrupt.
    try:
        snap = await graph.aget_state(config)
    except Exception:  # noqa: BLE001
        snap = None

    if snap is not None and (snap.next or (snap.tasks and any(
        getattr(t, "interrupts", None) for t in (snap.tasks or [])
    ))):
        # Pending interrupt → treat as resume with continue/skip-all friendly text
        interrupts = []
        for task in snap.tasks or []:
            interrupts.extend(list(getattr(task, "interrupts", None) or []))
        if interrupts:
            return await runtime.aresume(thread_id, "continue")
        slug = runtime._client_slug_from_values(snap.values or {})
        with runtime._target_scope(
            client_slug=slug,
            intake=(snap.values or {}).get("intake")
            if isinstance((snap.values or {}).get("intake"), dict)
            else None,
        ):
            result = await graph.ainvoke(None, config)
        values = (await graph.aget_state(config)).values or {}
        run_id2 = values.get("evidence_run_id") or rid
        if store is None and run_id2:
            try:
                store = EvidenceStore.open_existing(
                    runtime.settings.evidence_dir, str(run_id2)
                )
                runtime._evidence_by_run[store.run_id] = store
            except Exception:  # noqa: BLE001
                pass
        decorated = runtime._decorate_result(
            result, thread_id=thread_id, store=store, intake=is_intake
        )
        if decorated.get("awaiting_hitl"):
            return decorated
        if rid:
            write_run_status(
                runtime.settings.evidence_dir, str(run_id2 or rid), status="running"
            )
        return await runtime._continue_multi_after_resume(thread_id, decorated)

    # Evidence fallback: rebuild pending_ids from disk and re-enter assess.
    if not rid:
        return {
            "report": (
                "No interrupted audit checkpoint found. "
                "Start a new audit or reply from a message that still has "
                "`[AUDIT_CONTINUE:…]` / `[AUDIT_HITL:…]`."
            ),
            "awaiting_hitl": False,
            "messages": [],
        }

    assert store is not None or rid
    if store is None:
        store = EvidenceStore.open_existing(runtime.settings.evidence_dir, rid)
        runtime._evidence_by_run[rid] = store

    meta = store.read_run_meta()
    framework_id = str(
        meta.get("framework_id")
        or (thread_id.split(":")[-1] if ":" in thread_id else "")
    )
    host_id = str(meta.get("evidence_host_id") or "")
    if host_id:
        store.host_segment = host_id
    # Resolve framework folder under host if needed
    fw_key = f"{host_id}/{framework_id}" if host_id else framework_id
    disk_findings = store.load_findings(fw_key)
    if not disk_findings and framework_id:
        disk_findings = store.load_findings(framework_id)

    from auditor.checklist import load_checklist
    from auditor.frameworks import get_framework

    fw = get_framework(framework_id, runtime.settings.agents_dir)
    if fw is None:
        return {
            "report": f"Cannot continue: framework `{framework_id}` not found.",
            "awaiting_hitl": False,
        }
    checklist = load_checklist(fw.path)
    done = set(disk_findings.keys())
    pending = [rid_ for rid_ in checklist.ids() if rid_ not in done]
    meta_pending = meta.get("pending_ids")
    if isinstance(meta_pending, list) and meta_pending:
        pending = [str(x) for x in meta_pending if str(x) not in done]

    findings_objs: dict[str, Finding] = {}
    for req_id, raw in disk_findings.items():
        try:
            findings_objs[req_id] = Finding.model_validate(raw)
        except Exception:  # noqa: BLE001
            continue

    write_run_status(
        runtime.settings.evidence_dir,
        rid,
        status="running",
        thread_id=thread_id,
        pending_ids=pending,
        framework_id=framework_id,
    )

    continue_intake = meta.get("intake") if isinstance(meta.get("intake"), dict) else None
    continue_slug = str(
        meta.get("client_slug")
        or ((continue_intake or {}).get("client_slug") if continue_intake else "")
        or ""
    ).strip() or None

    if not pending:
        # All REQs done — finalize via graph update + finalize node path
        await graph.aupdate_state(
            config,
            {
                "findings": findings_objs,
                "pending_ids": [],
                "requirements": {r.id: r for r in checklist.requirements},
                "framework_id": framework_id,
                "framework_title": fw.title,
                "checklist_title": checklist.title,
                "evidence_run_id": rid,
                "evidence_run_dir": str(store.root),
                "evidence_host_id": host_id,
                "thread_id": thread_id,
                "user_request": str(meta.get("user_request") or "continue"),
                "intake_complete": True,
                "awaiting_hitl": False,
            },
            as_node="assess_parallel",
        )
        with runtime._target_scope(client_slug=continue_slug, intake=continue_intake):
            result = await graph.ainvoke(None, config)
        decorated = runtime._decorate_result(
            result, thread_id=thread_id, store=store
        )
        return await runtime._continue_multi_after_resume(thread_id, decorated)

    await graph.aupdate_state(
        config,
        {
            "findings": findings_objs,
            "pending_ids": pending,
            "requirements": {r.id: r for r in checklist.requirements},
            "framework_id": framework_id,
            "framework_title": fw.title,
            "checklist_title": checklist.title,
            "evidence_run_id": rid,
            "evidence_run_dir": str(store.root),
            "evidence_host_id": host_id,
            "thread_id": thread_id,
            "user_request": str(meta.get("user_request") or "continue"),
            "intake_complete": True,
            "awaiting_hitl": False,
            "retry_count": 0,
            "hitl_skipped": list(meta.get("hitl_skipped") or []),
        },
        as_node="load_framework",
    )
    with runtime._target_scope(client_slug=continue_slug, intake=continue_intake):
        result = await graph.ainvoke(None, config)
    decorated = runtime._decorate_result(result, thread_id=thread_id, store=store)
    if decorated.get("awaiting_hitl"):
        return decorated
    write_run_status(runtime.settings.evidence_dir, rid, status="completed")
    return await runtime._continue_multi_after_resume(thread_id, decorated)

async def arun_intake(runtime: AuditRuntime,
    user_text: str,
    *,
    run_id: str,
    thread_id: str,
    store: EvidenceStore,
) -> dict[str, Any]:
    """Run the intake questionnaire graph (may interrupt)."""
    report_lang = detect_report_language(user_text)
    initial: AuditorState = {
        "messages": [HumanMessage(content=user_text)],
        "user_request": truncate_text(
            user_text,
            runtime.settings.max_user_request_chars,
            "user_request",
        ),
        "report_language": report_lang.code,
        "evidence_run_id": store.run_id,
        "evidence_run_dir": str(store.root),
        "intake_complete": False,
        "intake": {},
        "thread_id": thread_id,
    }
    config = {"configurable": {"thread_id": thread_id}}
    result = await runtime.intake_graph.ainvoke(initial, config)
    return runtime._decorate_result(result, thread_id=thread_id, store=store, intake=True)

def interrupted_continue_message(runtime: AuditRuntime, thread_id: str, run_id: str) -> str:
    """Build operator-facing interrupt message with continue marker."""
    session_note = ""
    try:
        store = EvidenceStore.open_existing(runtime.settings.evidence_dir, run_id)
        meta = store.read_run_meta()
        sess = meta.get("results_session_number")
        client = meta.get("client_name") or run_id
        if sess is not None:
            session_note = (
                f"\nResults warehouse session **#{sess}** "
                f"(client `{client}`).\n"
                "Ask *which sessions need continue?* to list interrupted audits.\n"
            )
    except Exception:  # noqa: BLE001
        session_note = ""
    return format_continue_assistant_message(
        (
            "## Audit interrupted\n\n"
            f"Run `{run_id}` stopped before all requirements finished.\n"
            f"{session_note}"
            "Reply **continue** (or **продолжи**) to resume from the last checkpoint."
        ),
        thread_id,
    )

async def ensure_async_checkpointer(runtime: AuditRuntime) -> None:
    """Upgrade to AsyncSqliteSaver (required for ``ainvoke`` durability)."""
    if runtime._async_cp_ready and runtime._checkpoint_conn is not None:
        # Detect a closed aiosqlite connection (common after redeploy / WAL churn).
        try:
            conn = runtime._checkpoint_conn
            closed = bool(getattr(conn, "_connection", None) is None) or bool(
                getattr(conn, "_closed", False)
            )
            if not closed:
                return
        except Exception:  # noqa: BLE001
            pass
        runtime._async_cp_ready = False
    if runtime._async_cp_ready:
        return
    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        path = Path(runtime.settings.checkpoint_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Keep the async context manager open for the process lifetime.
        if getattr(runtime, "_sqlite_cm", None) is not None:
            try:
                await runtime._sqlite_cm.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            runtime._sqlite_cm = None
        runtime._sqlite_cm = AsyncSqliteSaver.from_conn_string(str(path))
        runtime._checkpointer = await runtime._sqlite_cm.__aenter__()
        runtime._checkpoint_conn = getattr(runtime._checkpointer, "conn", None)
        runtime.graph = runtime._build()
        runtime.intake_graph = runtime._build_intake()
        runtime._async_cp_ready = True
    except Exception:  # noqa: BLE001
        # Keep MemorySaver — process-local resume only.
        runtime._checkpointer = MemorySaver()
        runtime.graph = runtime._build()
        runtime.intake_graph = runtime._build_intake()
        runtime._async_cp_ready = True
        runtime._checkpoint_conn = None

def target_scope(runtime: AuditRuntime,
    *,
    client_slug: str | None = None,
    ssh_target: InventorySshTarget | None = None,
    intake: dict[str, Any] | None = None,
) -> Iterator[None]:
    """Bind run-scoped SSH/PG credentials for the duration of a graph call.

    Prefers ``client_slug``, else ``intake["client_slug"]``. Nested SSH host
    binds override SSH fields without clearing PostgreSQL overlays.
    """
    slug = (client_slug or "").strip()
    if not slug and intake:
        slug = str(intake.get("client_slug") or "").strip()
    with ExitStack() as stack:
        if slug:
            try:
                creds = read_client_credentials(runtime.settings.inventory_dir, slug)
            except (OSError, ValueError, FileNotFoundError):
                creds = {}
            if creds:
                stack.enter_context(bind_runtime_credentials(creds))
        if ssh_target is not None:
            stack.enter_context(bind_host_target(ssh_target))
        yield

def client_slug_from_values(runtime: AuditRuntime, values: dict[str, Any] | None) -> str | None:
    """Extract client slug from checkpoint/intake state when present."""
    if not values:
        return None
    intake = values.get("intake") if isinstance(values.get("intake"), dict) else {}
    slug = str(
        values.get("client_slug")
        or (intake or {}).get("client_slug")
        or ""
    ).strip()
    return slug or None


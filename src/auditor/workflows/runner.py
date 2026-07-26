"""Single-run lifecycle: arun_one, aresume, acontinue, intake invoke."""

from __future__ import annotations

import uuid
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Iterator

from langchain_core.messages import HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from auditor.asset_registry import get_asset_registry
from auditor.audit_registry import get_audit_registry
from auditor.client_registry import get_client_registry
from auditor.context import truncate_text
from auditor.evidence_store import EvidenceStore, bind_host_segment, new_run_id
from auditor.frameworks import get_framework
from auditor.hitl import format_continue_assistant_message
from auditor.intake import client_slug
from auditor.language import detect_report_language
from auditor.legacy_compat import assert_client_owns_run, require_audit_run_id, require_client_id
from auditor.progress import emit_phase
from auditor.result_identity_bind import attach_result_identity
from auditor.run_scope import (
    RunScopeIsolationError,
    assert_thread_belongs_to_run,
    checkpoint_thread_id,
    open_run_scope,
    parse_checkpoint_thread_id,
    resolve_run_scope,
    verify_registry_ownership,
)
from auditor.runtime_target import bind_runtime_credentials
from auditor.secrets_file import InventorySshTarget, bind_host_target, read_client_credentials
from auditor.session_store import find_run_for_thread, write_run_status
from auditor.state import AuditorState, Finding
from auditor.workflows.protocols import AuditRuntime

try:
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
except ImportError:  # pragma: no cover
    AsyncSqliteSaver = None  # type: ignore[misc, assignment]


async def arun_one(
    runtime: AuditRuntime,
    user_text: str,
    *,
    framework_id: str | None = None,
    run_id: str | None = None,
    thread_id: str | None = None,
    intake_state: dict[str, Any] | None = None,
    evidence_host_id: str | None = None,
    ssh_target: InventorySshTarget | None = None,
) -> dict[str, Any]:
    """Run a single-framework audit graph (optionally pinned).

    Checkpoint thread id and artifact root are derived from validated
    ``client_id`` + ``audit_run_id`` (CORE-005). Caller-supplied ``thread_id``
    cannot select another run's checkpoint scope.
    """
    rid = run_id or new_run_id()
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
            meta["results_session_number"] = intake_state["results_session_number"]
        if intake_state.get("audit_run_id"):
            meta["audit_run_id"] = intake_state["audit_run_id"]
    client_name = str((intake_state or {}).get("client_name") or meta.get("client_name") or "")
    slug = str(
        (intake_state or {}).get("client_slug")
        or (client_slug(client_name) if client_name else "")
        or "client"
    )
    client = get_client_registry(runtime.settings.evidence_dir).ensure_client(
        display_name=client_name or slug,
        slug=slug,
        client_id=str((intake_state or {}).get("client_id") or "") or None,
    )
    client_id = client.client_id
    registry = get_audit_registry(runtime.settings.evidence_dir)
    audit_run_id = str((intake_state or {}).get("audit_run_id") or "").strip()
    # Temporary thread until audit_run_id is known; replaced by canonical key.
    tid = f"audit-pending-{uuid.uuid4().hex[:12]}"
    if audit_run_id:
        require_audit_run_id(audit_run_id, context="arun_one")
        existing = registry.get_run(audit_run_id)
        if existing is None:
            # Explicit id from caller that is not yet registered — create once.
            registry.create_run(
                client_id=client_id,
                scope={"framework_id": framework_id or "", "client_slug": client.slug},
                evidence_run_id=store.run_id,
                base_thread_id=tid,
                audit_run_id=audit_run_id,
            )
            registry.mark_run_started(audit_run_id)
        else:
            assert_client_owns_run(
                audit_run_id=audit_run_id,
                run_client_id=existing.client_id,
                requested_client_id=client_id,
                context="arun_one",
            )
            if not existing.evidence_run_id:
                existing.evidence_run_id = store.run_id
                registry.save_run(existing)
    else:
        # New single-framework audit → new AuditRun (never reuse by client).
        arun = registry.create_run(
            client_id=client_id,
            scope={"framework_id": framework_id or "", "client_slug": client.slug},
            evidence_run_id=store.run_id,
            base_thread_id=tid,
        )
        registry.mark_run_started(arun.audit_run_id)
        audit_run_id = arun.audit_run_id
    # Canonical CORE-005 scope: thread + nested evidence + ownership manifest.
    scope = resolve_run_scope(
        runtime.settings.evidence_dir,
        client_id=client_id,
        audit_run_id=audit_run_id,
        client_slug=client.slug,
    )
    ns: list[str] = []
    if evidence_host_id:
        ns.append(evidence_host_id)
    if framework_id:
        ns.append(framework_id.split("/", 1)[-1])
    tid = checkpoint_thread_id(client_id, audit_run_id, *ns)
    if thread_id and thread_id.strip() and thread_id.strip() != tid:
        # Caller-supplied foreign threads cannot select another run's scope.
        try:
            assert_thread_belongs_to_run(
                thread_id,
                client_id=client_id,
                audit_run_id=audit_run_id,
                context="arun_one",
            )
            tid = thread_id.strip()
        except RunScopeIsolationError:
            tid = checkpoint_thread_id(client_id, audit_run_id, *ns)
    meta["thread_id"] = tid
    if store.run_id != scope.evidence_run_id:
        old_id = store.run_id
        store.rebind_run_id(scope.evidence_run_id)
        runtime._evidence_by_run.pop(old_id, None)
        runtime._evidence_by_run[store.run_id] = store
    run_row = registry.get_run(audit_run_id)
    if run_row is not None:
        run_row.evidence_run_id = store.run_id
        run_row.base_thread_id = scope.checkpoint_thread_id
        registry.save_run(run_row)
    await ensure_async_checkpointer(
        runtime,
        client_id=client_id,
        audit_run_id=audit_run_id,
    )
    asset_id = str((intake_state or {}).get("asset_id") or "")
    if not asset_id and ssh_target is not None:
        inv_key = ssh_target.inventory_key or ssh_target.label
        if inv_key or ssh_target.asset_id:
            asset_id = get_asset_registry(runtime.settings.evidence_dir).ensure_asset(
                client_id=client_id,
                inventory_key=inv_key or ssh_target.asset_id,
                label=ssh_target.label,
                ssh_host=ssh_target.host,
                asset_id=ssh_target.asset_id or None,
            )
        elif evidence_host_id and not evidence_host_id.replace(".", "").isdigit():
            # Hostname (not IP) may serve as stable inventory key.
            asset_id = get_asset_registry(runtime.settings.evidence_dir).ensure_asset(
                client_id=client_id,
                inventory_key=evidence_host_id,
                label=evidence_host_id,
                ssh_host=ssh_target.host if ssh_target else "",
            )
    if not asset_id:
        # Client-scoped synthetic asset for hostless framework runs.
        asset_id = get_asset_registry(runtime.settings.evidence_dir).ensure_asset(
            client_id=client_id,
            inventory_key=f"client:{client_id}",
            label=client_name or client_id,
        )
    fw_version = str((intake_state or {}).get("framework_version") or "")
    if not fw_version and framework_id:
        bare = framework_id.split("/", 1)[-1]
        fw_obj = get_framework(bare, runtime.settings.agents_dir)
        fw_version = str(getattr(fw_obj, "version", "") or "") if fw_obj else ""
    meta["asset_id"] = asset_id
    meta["client_id"] = client_id
    meta["audit_run_id"] = audit_run_id
    if fw_version:
        meta["framework_version"] = fw_version
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
            initial["results_session_number"] = int(intake_state["results_session_number"])
    if framework_id:
        initial["framework_id"] = framework_id
    if evidence_host_id:
        initial["evidence_host_id"] = evidence_host_id
    if audit_run_id:
        initial["audit_run_id"] = audit_run_id
    if asset_id:
        initial["asset_id"] = asset_id
    if client_id:
        initial["client_id"] = client_id
    if fw_version:
        initial["framework_version"] = fw_version
    config = {"configurable": {"thread_id": tid}}

    async def _invoke() -> dict[str, Any]:
        """Run the main graph and decorate with HITL/intake messaging."""
        result = await runtime.graph.ainvoke(initial, config)
        return runtime._decorate_result(result, thread_id=tid, store=store)

    intake_for_scope = (intake_state.get("intake") if intake_state else None) or intake_state or {}
    if not isinstance(intake_for_scope, dict):
        intake_for_scope = {}
    with runtime._target_scope(intake=intake_for_scope, ssh_target=ssh_target):
        with bind_host_segment(evidence_host_id):
            return await _invoke()


async def aresume(
    runtime: AuditRuntime,
    thread_id: str,
    user_text: str,
    *,
    client_id: str | None = None,
    audit_run_id: str | None = None,
) -> dict[str, Any]:
    """Resume a graph paused on intake or ``human_gate``.

    CORE-005: resume is bound to exact ``client_id`` + ``audit_run_id``. A
    foreign ``thread_id`` cannot open another run's checkpoint.
    """
    cid, arid, tid = await _resolve_resume_identity(
        runtime,
        thread_id=thread_id,
        client_id=client_id,
        audit_run_id=audit_run_id,
        context="aresume",
    )
    await ensure_async_checkpointer(runtime, client_id=cid, audit_run_id=arid)
    config = {"configurable": {"thread_id": tid}}
    is_intake = ":intake" in tid or tid.endswith("intake")
    graph = runtime.intake_graph if is_intake else runtime.graph
    try:
        pre = await graph.aget_state(config)
        pre_values = pre.values or {}
    except Exception:  # noqa: BLE001
        pre_values = {}
    # Checkpoint state must not claim a different audit-run identity.
    state_cid = str(pre_values.get("client_id") or "").strip()
    state_arid = str(pre_values.get("audit_run_id") or "").strip()
    if state_cid and state_cid != cid:
        raise RunScopeIsolationError(
            f"checkpoint client_id={state_cid!r} does not match resume client_id={cid!r}"
        )
    if state_arid and state_arid != arid:
        raise RunScopeIsolationError(
            f"checkpoint audit_run_id={state_arid!r} does not match resume audit_run_id={arid!r}"
        )
    slug = runtime._client_slug_from_values(pre_values)
    with runtime._target_scope(
        client_slug=slug,
        intake=pre_values.get("intake") if isinstance(pre_values.get("intake"), dict) else None,
    ):
        result = await graph.ainvoke(Command(resume=user_text), config)
    snap = await graph.aget_state(config)
    values = snap.values or {}
    run_id = values.get("evidence_run_id") or ""
    store = runtime._evidence_by_run.get(run_id)
    if store is None and run_id:
        try:
            store = EvidenceStore.open_existing(
                runtime.settings.evidence_dir,
                str(run_id),
                client_id=cid,
                audit_run_id=arid,
            )
            runtime._evidence_by_run[store.run_id] = store
        except Exception:  # noqa: BLE001
            store = None
    if store is not None:
        store.require_ownership(client_id=cid, audit_run_id=arid)
    decorated = runtime._decorate_result(result, thread_id=tid, store=store, intake=is_intake)
    if decorated.get("awaiting_hitl"):
        return decorated

    if is_intake and values.get("intake_complete"):
        # Continue into framework audits using intake answers.
        session = runtime._forget_multi_session(tid) or {}
        user_req = session.get("user_text") or values.get("user_request") or user_text
        base_thread = session.get("base_thread") or checkpoint_thread_id(cid, arid)
        run_id = values.get("evidence_run_id") or session.get("run_id") or run_id
        intake = values.get("intake") or {}
        if isinstance(intake, dict):
            intake = {
                **intake,
                "client_id": cid,
                "audit_run_id": arid,
            }
        return await runtime._start_frameworks_after_intake(
            user_text=str(user_req),
            base_thread=base_thread,
            run_id=str(run_id),
            intake=intake if isinstance(intake, dict) else {},
        )

    # If this thread was part of a multi-framework run, continue the queue.
    return await runtime._continue_multi_after_resume(tid, decorated)


async def _resolve_resume_identity(
    runtime: AuditRuntime,
    *,
    thread_id: str,
    client_id: str | None,
    audit_run_id: str | None,
    context: str,
) -> tuple[str, str, str]:
    """Validate resume identity and return ``(client_id, audit_run_id, thread_id)``."""
    tid = (thread_id or "").strip()
    if not tid:
        raise RunScopeIsolationError(f"{context}: thread_id is required")
    cid = (client_id or "").strip()
    arid = (audit_run_id or "").strip()
    registry = get_audit_registry(runtime.settings.evidence_dir)
    parsed = parse_checkpoint_thread_id(tid)
    if parsed is not None:
        parsed_cid, parsed_arid = parsed
        if not cid:
            cid = parsed_cid
        if not arid:
            arid = parsed_arid
        if cid != parsed_cid or arid != parsed_arid:
            raise RunScopeIsolationError(
                f"{context}: thread_id identity ({parsed_cid!r}, {parsed_arid!r}) "
                f"conflicts with requested ({cid!r}, {arid!r})"
            )

    if arid:
        arid = require_audit_run_id(arid, context=context)
        arun = registry.get_run(arid)
        if arun is None:
            raise RunScopeIsolationError(f"{context}: unknown audit_run_id {arid!r}")
        if cid:
            cid = require_client_id(cid, context=context)
            verify_registry_ownership(
                audit_run_id=arid,
                run_client_id=arun.client_id,
                requested_client_id=cid,
                context=context,
            )
        else:
            cid = require_client_id(arun.client_id, context=context)
    elif cid:
        raise RunScopeIsolationError(
            f"{context}: audit_run_id is required with client_id (no latest-run fallback)"
        )
    else:
        # Soft path for in-process tests: load checkpoint once from current saver
        # and require it already carries both identity fields.
        await ensure_async_checkpointer(runtime)
        is_intake = ":intake" in tid or tid.endswith("intake")
        graph = runtime.intake_graph if is_intake else runtime.graph
        try:
            pre = await graph.aget_state({"configurable": {"thread_id": tid}})
            values = pre.values or {}
        except Exception as exc:  # noqa: BLE001
            raise RunScopeIsolationError(
                f"{context}: cannot load checkpoint for thread_id={tid!r}"
            ) from exc
        cid = str(values.get("client_id") or "").strip()
        arid = str(values.get("audit_run_id") or "").strip()
        if not cid or not arid:
            raise RunScopeIsolationError(
                f"{context}: required client_id and audit_run_id for resume "
                f"(thread_id={tid!r}); refusing unbound checkpoint access"
            )
        cid = require_client_id(cid, context=context)
        arid = require_audit_run_id(arid, context=context)
        arun = registry.get_run(arid)
        if arun is None:
            raise RunScopeIsolationError(f"{context}: unknown audit_run_id {arid!r}")
        verify_registry_ownership(
            audit_run_id=arid,
            run_client_id=arun.client_id,
            requested_client_id=cid,
            context=context,
        )

    arun = registry.get_run(arid)
    registered_base = ""
    if arun is not None:
        registered_base = str(arun.base_thread_id or "").strip()
    assert_thread_belongs_to_run(
        tid,
        client_id=cid,
        audit_run_id=arid,
        context=context,
        registered_base_thread_id=registered_base,
    )
    # Artifact ownership must match before any resume mutation.
    evid = ""
    if arun is not None and arun.evidence_run_id:
        evid = arun.evidence_run_id
    try:
        if evid:
            EvidenceStore.open_existing(
                runtime.settings.evidence_dir,
                evid,
                client_id=cid,
                audit_run_id=arid,
            )
        else:
            # Prefer slug from registry scope when present.
            slug = ""
            if arun is not None and isinstance(arun.scope, dict):
                slug = str(arun.scope.get("client_slug") or "")
            scope = resolve_run_scope(
                runtime.settings.evidence_dir,
                client_id=cid,
                audit_run_id=arid,
                client_slug=slug or None,
            )
            if scope.artifact_root.is_dir():
                open_run_scope(
                    runtime.settings.evidence_dir,
                    client_id=cid,
                    audit_run_id=arid,
                    client_slug=scope.client_slug,
                    create=False,
                )
    except FileNotFoundError:
        # Brand-new pause before evidence rebind — checkpoint identity still binds.
        pass
    return cid, arid, tid


async def acontinue(
    runtime: AuditRuntime,
    thread_id: str,
    *,
    run_id: str | None = None,
    client_id: str | None = None,
    audit_run_id: str | None = None,
) -> dict[str, Any]:
    """Resume an interrupted mid-assess (or HITL) run after disconnect/restart.

    CORE-005: active run identity must be explicit ``client_id`` +
    ``audit_run_id`` (or resolvable from ``run_id`` / registry). Never selects
    "latest interrupted" as fallback. Foreign ``thread_id`` values are rejected.
    """
    emit_phase(f"Continuing audit from checkpoint (`{thread_id}`)…")
    rid = (run_id or "").strip()
    arid = (audit_run_id or "").strip()
    cid = (client_id or "").strip()
    registry = get_audit_registry(runtime.settings.evidence_dir)

    if rid.startswith("arun_"):
        arid = rid
        rid = ""
    if arid:
        arid = require_audit_run_id(arid, context="acontinue")
        arun = registry.get_run(arid)
        if arun is None:
            return {
                "report": f"Unknown audit_run_id `{arid}`.",
                "awaiting_hitl": False,
                "messages": [],
            }
        if cid:
            verify_registry_ownership(
                audit_run_id=arid,
                run_client_id=arun.client_id,
                requested_client_id=cid,
                context="acontinue",
            )
        else:
            cid = require_client_id(arun.client_id, context="acontinue")
        rid = arun.evidence_run_id or rid
        if arun.status.value == "cancelled":
            registry.resume_run(arid)

    if not arid:
        # Prefer in-memory multi-session bound to this thread.
        sess = (
            runtime._multi_sessions.get(thread_id) if hasattr(runtime, "_multi_sessions") else None
        )
        if isinstance(sess, dict) and sess.get("audit_run_id"):
            arid = str(sess.get("audit_run_id") or "")
            cid = cid or str(sess.get("client_id") or "")
            rid = rid or str(sess.get("run_id") or "")
        elif isinstance(sess, dict) and sess.get("run_id"):
            rid = rid or str(sess.get("run_id") or "")
        else:
            found = find_run_for_thread(runtime.settings.evidence_dir, thread_id)
            if found:
                rid, meta = found
                arid = arid or str(meta.get("audit_run_id") or "")
                cid = cid or str(meta.get("client_id") or "")

    if not arid or not cid:
        # Fail closed — do not continue without both identity fields.
        return {
            "report": (
                "Continue requires explicit client_id and audit_run_id "
                "(CORE-005: no latest-run / unbound-thread fallback)."
            ),
            "awaiting_hitl": False,
            "messages": [],
        }

    try:
        cid, arid, tid = await _resolve_resume_identity(
            runtime,
            thread_id=thread_id,
            client_id=cid,
            audit_run_id=arid,
            context="acontinue",
        )
    except RunScopeIsolationError as exc:
        return {
            "report": f"Isolation error: {exc}",
            "awaiting_hitl": False,
            "messages": [],
        }

    await ensure_async_checkpointer(runtime, client_id=cid, audit_run_id=arid)
    config = {"configurable": {"thread_id": tid}}
    is_intake = ":intake" in tid or tid.endswith("intake")
    graph = runtime.intake_graph if is_intake else runtime.graph

    store = None
    if rid:
        runtime._reload_multi_sessions(rid)
        store = runtime._evidence_by_run.get(rid)
        if store is None:
            try:
                store = EvidenceStore.open_existing(
                    runtime.settings.evidence_dir,
                    rid,
                    client_id=cid,
                    audit_run_id=arid,
                )
                runtime._evidence_by_run[rid] = store
            except Exception:  # noqa: BLE001
                store = None
    if store is None:
        arun = registry.get_run(arid)
        if arun is not None and arun.evidence_run_id:
            try:
                store = EvidenceStore.open_existing(
                    runtime.settings.evidence_dir,
                    arun.evidence_run_id,
                    client_id=cid,
                    audit_run_id=arid,
                )
                runtime._evidence_by_run[store.run_id] = store
                rid = store.run_id
            except Exception:  # noqa: BLE001
                store = None

    # Prefer LangGraph checkpoint if the graph still has work / interrupt.
    try:
        snap = await graph.aget_state(config)
    except Exception:  # noqa: BLE001
        snap = None

    if snap is not None and (
        snap.next
        or (snap.tasks and any(getattr(t, "interrupts", None) for t in (snap.tasks or [])))
    ):
        # Pending interrupt → treat as resume with continue/skip-all friendly text
        interrupts = []
        for task in snap.tasks or []:
            interrupts.extend(list(getattr(task, "interrupts", None) or []))
        if interrupts:
            return await runtime.aresume(
                tid,
                "continue",
                client_id=cid,
                audit_run_id=arid,
            )
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
                    runtime.settings.evidence_dir,
                    str(run_id2),
                    client_id=cid,
                    audit_run_id=arid,
                )
                runtime._evidence_by_run[store.run_id] = store
            except Exception:  # noqa: BLE001
                pass
        decorated = runtime._decorate_result(result, thread_id=tid, store=store, intake=is_intake)
        if decorated.get("awaiting_hitl"):
            return decorated
        if rid:
            write_run_status(runtime.settings.evidence_dir, str(run_id2 or rid), status="running")
        return await runtime._continue_multi_after_resume(tid, decorated)

    # Evidence fallback: rebuild pending_ids from disk and re-enter assess.
    if not rid:
        return {
            "report": (
                "No audit run bound to this thread. "
                "Pass an explicit evidence `run_id` / `audit_run_id`, or reply "
                "from a message that still has `[AUDIT_CONTINUE:…]` / "
                "`[AUDIT_HITL:…]` (CORE-002: no latest-run fallback)."
            ),
            "awaiting_hitl": False,
            "messages": [],
        }

    assert store is not None or rid
    if store is None:
        store = EvidenceStore.open_existing(
            runtime.settings.evidence_dir,
            rid,
            client_id=cid,
            audit_run_id=arid,
        )
        runtime._evidence_by_run[rid] = store
    store.require_ownership(client_id=cid, audit_run_id=arid)

    meta = store.read_run_meta()
    framework_id = str(meta.get("framework_id") or (tid.split(":")[-1] if ":" in tid else ""))
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
    done = store.load_finding_requirement_ids(fw_key) or store.load_finding_requirement_ids(
        framework_id
    )
    pending = [rid_ for rid_ in checklist.ids() if rid_ not in done]
    meta_pending = meta.get("pending_ids")
    if isinstance(meta_pending, list) and meta_pending:
        pending = [str(x) for x in meta_pending if str(x) not in done]

    findings_objs: dict[str, Finding] = {}
    for _key, raw in disk_findings.items():
        try:
            finding = Finding.model_validate(raw)
            if not finding.result_id:
                attach_result_identity(
                    finding,
                    state={
                        "client_id": str(meta.get("client_id") or ""),
                        "client_name": str(meta.get("client_name") or ""),
                        "audit_run_id": str(meta.get("audit_run_id") or ""),
                        "asset_id": str(meta.get("asset_id") or ""),
                        "framework_version": str(
                            meta.get("framework_version") or getattr(fw, "version", "") or ""
                        ),
                    },
                    framework_id=framework_id,
                    framework_version=str(
                        meta.get("framework_version") or getattr(fw, "version", "") or ""
                    ),
                    existing=raw,
                )
            if finding.result_id:
                findings_objs[finding.result_id] = finding
        except Exception:  # noqa: BLE001
            continue

    write_run_status(
        runtime.settings.evidence_dir,
        rid,
        status="running",
        thread_id=tid,
        pending_ids=pending,
        framework_id=framework_id,
    )

    continue_intake = meta.get("intake") if isinstance(meta.get("intake"), dict) else None
    continue_slug = (
        str(
            meta.get("client_slug")
            or ((continue_intake or {}).get("client_slug") if continue_intake else "")
            or ""
        ).strip()
        or None
    )

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
                "thread_id": tid,
                "user_request": str(meta.get("user_request") or "continue"),
                "intake_complete": True,
                "awaiting_hitl": False,
            },
            as_node="assess_parallel",
        )
        with runtime._target_scope(client_slug=continue_slug, intake=continue_intake):
            result = await graph.ainvoke(None, config)
        decorated = runtime._decorate_result(result, thread_id=tid, store=store)
        return await runtime._continue_multi_after_resume(tid, decorated)

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
            "thread_id": tid,
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
    decorated = runtime._decorate_result(result, thread_id=tid, store=store)
    if decorated.get("awaiting_hitl"):
        return decorated
    write_run_status(runtime.settings.evidence_dir, rid, status="completed")
    return await runtime._continue_multi_after_resume(tid, decorated)


async def arun_intake(
    runtime: AuditRuntime,
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


async def ensure_async_checkpointer(
    runtime: AuditRuntime,
    *,
    client_id: str | None = None,
    audit_run_id: str | None = None,
) -> None:
    """Upgrade to AsyncSqliteSaver scoped per audit run when identity is known.

    CORE-005: when ``client_id`` + ``audit_run_id`` are provided, open
    ``<evidence_dir>/.checkpoints/<client_id>/<audit_run_id>.sqlite``. Otherwise
    fall back to ``Settings.checkpoint_path`` (process-local / legacy tests).
    """
    path: Path
    scope_key = ""
    if client_id and audit_run_id:
        scope = resolve_run_scope(
            runtime.settings.evidence_dir,
            client_id=client_id,
            audit_run_id=audit_run_id,
        )
        path = scope.checkpoint_db_path
        scope_key = f"{scope.client_id}:{scope.audit_run_id}"
    else:
        path = Path(runtime.settings.checkpoint_path)
        scope_key = f"legacy:{path.resolve()}"

    current_key = str(getattr(runtime, "_checkpoint_scope_key", "") or "")
    if (
        runtime._async_cp_ready
        and runtime._checkpoint_conn is not None
        and current_key == scope_key
    ):
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

    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        path.parent.mkdir(parents=True, exist_ok=True)
        sqlite_cm = getattr(runtime, "_sqlite_cm", None)
        if sqlite_cm is not None:
            try:
                await sqlite_cm.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            runtime._sqlite_cm = None
        runtime._sqlite_cm = AsyncSqliteSaver.from_conn_string(str(path))
        sqlite_cm = runtime._sqlite_cm
        assert sqlite_cm is not None
        runtime._checkpointer = await sqlite_cm.__aenter__()
        runtime._checkpoint_conn = getattr(runtime._checkpointer, "conn", None)
        runtime._checkpoint_scope_key = scope_key
        runtime.graph = runtime._build()
        runtime.intake_graph = runtime._build_intake()
        runtime._async_cp_ready = True
    except Exception:  # noqa: BLE001
        # Keep MemorySaver — process-local resume only.
        runtime._checkpointer = MemorySaver()
        runtime._checkpoint_scope_key = scope_key
        runtime.graph = runtime._build()
        runtime.intake_graph = runtime._build_intake()
        runtime._async_cp_ready = True
        runtime._checkpoint_conn = None


def target_scope(
    runtime: AuditRuntime,
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
    slug = str(values.get("client_slug") or (intake or {}).get("client_slug") or "").strip()
    return slug or None

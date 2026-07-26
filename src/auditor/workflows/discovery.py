"""Framework routing, checklist load, and host_facts collection."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
)
from langgraph.graph.message import REMOVE_ALL_MESSAGES

from auditor.context import count_tool_rounds, truncate_text
from auditor.domain.assessment_result import AssessmentResult, ResultIdentity
from auditor.domain.result_identity import new_result_id
from auditor.evidence_store import EvidenceStore
from auditor.frameworks import (
    frameworks_catalog_text,
    frameworks_detect_catalog_text,
    get_framework,
    list_frameworks,
    load_framework_checklist,
    route_framework,
)
from auditor.host_facts import (
    DriftItem,
    HostFacts,
    format_host_facts_markdown,
    merge_facts_from_raw,
    parse_host_facts_json,
    write_host_facts_json,
)
from auditor.intake import client_slug
from auditor.language import detect_report_language
from auditor.progress import emit_phase, emit_req_status
from auditor.prompts import (
    HOST_FACTS_FILL_PROMPT,
    HOST_FACTS_FILL_SYSTEM_PROMPT,
    HOST_FACTS_FORCE_PROMPT,
    HOST_FACTS_PROMPT,
    HOST_FACTS_SYSTEM_PROMPT,
    SOFTWARE_FRAMEWORK_ROUTE_PROMPT,
    SOFTWARE_FRAMEWORK_ROUTE_SYSTEM,
)
from auditor.runtime_target import effective_settings
from auditor.secrets_file import InventorySshTarget, list_client_ssh_targets
from auditor.state import AuditorState, Finding
from auditor.workflows.helpers import _as_finding, _extract_json
from auditor.workflows.protocols import AuditRuntime


async def route_framework_node(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
    """Node: choose ``agents/<framework>.md`` (honors pinned ``framework_id``)."""
    user_request = state.get("user_request") or ""
    if not user_request:
        for msg in reversed(state.get("messages") or []):
            if isinstance(msg, HumanMessage):
                user_request = str(msg.content)
                break
    user_request = truncate_text(
        user_request,
        runtime.settings.max_user_request_chars,
        "user_request",
    )
    report_lang = detect_report_language(user_request)

    pinned = state.get("framework_id") or ""
    try:
        if pinned:
            fw = get_framework(pinned, runtime.settings.agents_dir)
            if fw is None:
                raise FileNotFoundError(f"Pinned framework `{pinned}` not found in agents/")
        else:
            fw = route_framework(
                user_request,
                runtime.settings.agents_dir,
                preferred_language=report_lang.code,
            )
    except FileNotFoundError as exc:
        return {
            "user_request": user_request,
            "report_language": report_lang.code,
            "error": str(exc),
            "framework_id": "",
            "framework_title": "",
            "pending_ids": [],
            "requirements": {},
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                AIMessage(content=str(exc)),
            ],
        }

    catalog = frameworks_catalog_text(runtime.settings.agents_dir)
    return {
        "user_request": user_request,
        "report_language": report_lang.code,
        "framework_id": fw.id,
        "framework_title": fw.title,
        "retry_count": 0,
        "error": None,
        "messages": [
            RemoveMessage(id=REMOVE_ALL_MESSAGES),
            SystemMessage(
                content=(
                    f"Selected framework `{fw.id}` ({fw.title}) from agents/.\n"
                    f"Report language: {report_lang.name} (`{report_lang.code}`).\n"
                    f"{catalog}"
                )
            ),
        ],
    }


async def load_framework(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
    """Node: load the drop-in Markdown checklist for the selected framework."""
    if state.get("error") and not state.get("framework_id"):
        return {"pending_ids": [], "requirements": {}}

    selected = get_framework(
        state.get("framework_id") or "",
        runtime.settings.agents_dir,
    )
    if selected is None:
        # Fallback: route again from user text.
        selected = route_framework(
            state.get("user_request") or "",
            runtime.settings.agents_dir,
            preferred_language=str(state.get("report_language") or ""),
        )
    checklist = load_framework_checklist(selected)
    req_map = checklist.by_id()
    store = runtime._store_from_state(state)
    host_id = str(state.get("evidence_host_id") or "").strip()
    if store is not None and host_id:
        store.host_segment = host_id

    # Reuse findings already written (e.g. host_facts.md during intake discovery).
    # Index by result_id (CORE-003); never by requirement_id alone.
    from auditor.result_identity_bind import attach_result_identity

    existing: dict[str, Finding] = {}
    pending: list[str] = []
    for rid in checklist.ids():
        raw = store.load_finding(selected.id, rid) if store is not None else None
        if raw:
            try:
                finding = _as_finding(raw)
                if not finding.result_id:
                    attach_result_identity(
                        finding,
                        state=state,
                        framework_id=selected.id,
                        framework_version=str(getattr(selected, "version", "") or ""),
                        existing=raw,
                    )
                if finding.result_id:
                    existing[finding.result_id] = finding
                    continue
            except Exception:  # noqa: BLE001
                pass
        pending.append(rid)

    reused = len(existing)
    msg = f"Loaded {len(req_map)} requirements from {selected.path}" + (
        f" ({reused} already assessed)." if reused else "."
    )
    return {
        "framework_id": selected.id,
        "framework_title": selected.title,
        "framework_version": str(getattr(selected, "version", "") or ""),
        "checklist_title": checklist.title,
        "requirements": req_map,
        "pending_ids": pending,
        "findings": existing,
        "report": "",
        "messages": [
            AIMessage(
                content=msg,
                name="auditor",
            )
        ],
    }


async def collect_host_facts(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
    """Gather host facts and copy existing INVENTORY.md without rewriting it."""
    if state.get("error") and not (state.get("requirements") or {}):
        return {}

    intake = dict(state.get("intake") or {})
    has_access = bool(state.get("has_access") or intake.get("has_access"))
    client_name = str(state.get("client_name") or intake.get("client_name") or "client")
    host_id = str(state.get("evidence_host_id") or "").strip()
    lang = runtime._report_language(state)
    facts_md = ""
    drift_md = ""
    drift_items: list[DriftItem] = []
    facts = None

    if has_access and effective_settings(runtime.settings).ssh_host:
        store = runtime._store_from_state(state)
        # Reuse intake discovery artifacts (avoid re-running host_facts.md).
        if store is not None:
            if host_id:
                store.host_segment = host_id
            facts_path = store.host_root(host_id or None) / "host_facts.json"
            if facts_path.is_file():
                try:
                    payload = json.loads(facts_path.read_text(encoding="utf-8"))
                    facts = parse_host_facts_json(
                        payload.get("facts") or payload,
                        ssh_host=str(effective_settings(runtime.settings).ssh_host or ""),
                    )
                    # Retry only when prior discovery failed with no identity.
                    if facts.error and not (facts.hostname or facts.os_id):
                        facts = None
                    elif facts is not None:
                        facts.raw["host_facts_source"] = str(
                            (facts.raw or {}).get("host_facts_source") or "reuse"
                        )
                except Exception:  # noqa: BLE001
                    facts = None
        if facts is None:
            facts = await runtime._collect_host_facts(
                store=store,
                host_id=host_id,
                user_request=str(state.get("user_request") or ""),
            )
        facts_md = format_host_facts_markdown(facts, None, language=lang.code)

        if store is not None and facts is not None:
            if host_id:
                store.host_segment = host_id
            facts_base = store.host_root(host_id or None)
            write_host_facts_json(facts_base / "host_facts.json", facts, drift_items)
            (facts_base / "host_facts.md").write_text(facts_md, encoding="utf-8")

        if facts is not None:
            inv_path = (
                Path(runtime.settings.inventory_dir) / client_slug(client_name) / "INVENTORY.md"
            )
            if store is not None:
                dest = store.root / "INVENTORY.md"
                if inv_path.is_file():
                    dest.write_text(
                        inv_path.read_text(encoding="utf-8"),
                        encoding="utf-8",
                    )
    else:
        # No live access: reuse existing inventory only; do not auto-fill.
        inv_path = Path(runtime.settings.inventory_dir) / client_slug(client_name) / "INVENTORY.md"
        store = runtime._store_from_state(state)
        if store is not None and inv_path.is_file():
            (store.root / "INVENTORY.md").write_text(
                inv_path.read_text(encoding="utf-8"), encoding="utf-8"
            )

    return {
        "host_facts_md": facts_md,
        "cmdb_drift_md": drift_md,
        "messages": [
            AIMessage(
                content=facts_md or "Host facts: skipped (no SSH access).",
                name="auditor",
            )
        ],
    }


async def collect_host_facts_dispatch(
    runtime: AuditRuntime,
    *,
    store: EvidenceStore | None = None,
    host_id: str = "",
    user_request: str = "",
    extra_binaries: list[str] | None = None,
) -> HostFacts:
    """Run ``agents/host_facts.md`` (fallback: compact SSH discovery)."""
    del extra_binaries  # routing hints stay in framework detect / LLM tools
    return await runtime._collect_host_facts_llm(
        store=store,
        host_id=host_id,
        user_request=user_request,
    )


async def collect_host_facts_llm(
    runtime: AuditRuntime,
    *,
    store: EvidenceStore | None = None,
    host_id: str = "",
    user_request: str = "",
) -> HostFacts:
    """Assess ``agents/host_facts.md`` then fill ``HostFacts`` for routing.

    Intake step 2 (access=yes) uses this path so discovery follows the same
    checklist REQs as a normal host_facts audit. Falls back to compact SSH
    discovery when the framework file is missing.
    """
    ssh_host = str(effective_settings(runtime.settings).ssh_host or "")
    if store is not None and host_id:
        store.host_segment = host_id

    fw = get_framework("host_facts", runtime.settings.agents_dir)
    if fw is None:
        return await runtime._collect_host_facts_compact(
            store=store,
            host_id=host_id,
            user_request=user_request,
        )

    checklist = load_framework_checklist(fw)
    req_map = checklist.by_id()
    pending = list(checklist.ids())
    if not pending:
        return await runtime._collect_host_facts_compact(
            store=store,
            host_id=host_id,
            user_request=user_request,
        )

    user_req = truncate_text(
        user_request or "Discover host inventory for audit routing.",
        runtime.settings.max_user_request_chars,
        "user_request",
    )
    limit = max(1, runtime.settings.max_parallel_assessments)
    sem = asyncio.Semaphore(limit)
    emit_phase(
        f"Discovery: assessing {len(pending)} `host_facts` requirement(s) (concurrency={limit})…",
        framework_id="host_facts",
    )

    async def _worker(req_id: str) -> AssessmentResult:
        async with sem:
            req_title = req_map[req_id].title
            emit_req_status(
                req_id,
                "started",
                framework_id="host_facts",
                requirement_title=req_title,
                text=f"Discovery `{req_id}: {req_title}`…",
            )
            finding: Finding | AssessmentResult
            try:
                finding = await runtime._fill_requirement_cells(
                    req_id=req_id,
                    requirement=req_map[req_id],
                    user_request=user_req,
                    framework_id="host_facts",
                    store=store,
                    ssh_only=True,
                )
            except Exception as exc:  # noqa: BLE001
                from auditor.result_identity_bind import attach_result_identity

                err_result = AssessmentResult.from_execution_error(
                    identity=ResultIdentity(
                        result_id=new_result_id(),
                        client_id="",
                        audit_run_id="",
                        asset_id="",
                        framework_id="host_facts",
                        framework_version="",
                        requirement_id=req_id,
                    ),
                    exc=exc,
                    title=req_map[req_id].title,
                    severity=req_map[req_id].severity,
                    category=req_map[req_id].category,
                    pass_criteria=req_map[req_id].pass_criteria,
                )
                if store is not None:
                    meta = store.read_run_meta()
                    finding = attach_result_identity(
                        err_result,
                        state={
                            "client_id": str(meta.get("client_id") or ""),
                            "audit_run_id": str(meta.get("audit_run_id") or ""),
                            "asset_id": str(meta.get("asset_id") or ""),
                            "framework_version": str(meta.get("framework_version") or "1"),
                        },
                        framework_id="host_facts",
                        framework_version=str(meta.get("framework_version") or "1"),
                    )
                    store.write_finding("host_facts", req_id, finding.to_persist_dict())
                else:
                    finding = err_result
            emit_req_status(
                req_id,
                finding.status,
                framework_id="host_facts",
                requirement_title=req_map[req_id].title,
            )
            if isinstance(finding, AssessmentResult):
                return finding
            return AssessmentResult.from_finding(finding)

    findings = await asyncio.gather(*(_worker(rid) for rid in pending))
    chunks: list[str] = []
    raw: dict[str, str] = {}
    for finding in findings:
        rid = finding.requirement_id
        if store is not None:
            tool_text = store.load_evidence_text(
                "host_facts",
                rid,
                max_chars=runtime.settings.max_tool_output_chars,
            )
            if tool_text:
                raw[f"req_{rid}"] = tool_text
                chunks.append(f"[{rid} tools]\n{tool_text}")
        obs = str(
            getattr(finding, "observation", None) or getattr(finding, "evidence", None) or ""
        ).strip()
        if obs:
            chunks.append(f"[{rid} {finding.status}] {finding.title}: {obs}")

    evidence = "\n---\n".join(c.strip() for c in chunks if c and c.strip())
    evidence = truncate_text(
        evidence,
        runtime.settings.max_tool_output_chars * 2,
        "host_facts_evidence",
    )
    facts = await runtime._facts_from_host_facts_evidence(
        evidence=evidence,
        raw=raw,
        ssh_host=ssh_host,
        source="checklist",
    )
    if not facts.error and any(f.status == "error" for f in findings):
        # Surface SSH/tool failures for routing when fill did not set error.
        err_bits = [
            f"{f.requirement_id}: "
            f"{getattr(f, 'observation', None) or getattr(f, 'evidence', None) or ''}"
            for f in findings
            if f.status == "error"
            and (getattr(f, "observation", None) or getattr(f, "evidence", None))
        ]
        if err_bits and "ssh error" in " ".join(err_bits).lower():
            facts.error = err_bits[0][:500]
    return facts


async def collect_host_facts_compact(
    runtime: AuditRuntime,
    *,
    store: EvidenceStore | None = None,
    host_id: str = "",
    user_request: str = "",
) -> HostFacts:
    """SSH-only tool loop + JSON fill (used when host_facts.md is missing)."""
    ssh_host = str(effective_settings(runtime.settings).ssh_host or "")
    evidence_fw = "host_facts"
    evidence_req = "discover"
    if store is not None and host_id:
        store.host_segment = host_id

    messages: list = [
        SystemMessage(content=HOST_FACTS_SYSTEM_PROMPT),
        HumanMessage(
            content=HOST_FACTS_PROMPT.format(
                user_request=truncate_text(
                    user_request or "Discover host inventory for audit routing.",
                    runtime.settings.max_user_request_chars,
                    "user_request",
                ),
                ssh_host=ssh_host or "(unknown)",
            )
        ),
    ]
    chunks: list[str] = []
    raw: dict[str, str] = {}
    max_rounds = runtime.settings.max_tool_rounds_per_item
    tool_idx = 0

    for _ in range(max_rounds + 1):
        rounds = count_tool_rounds(messages)
        if rounds >= max_rounds:
            messages.append(HumanMessage(content=HOST_FACTS_FORCE_PROMPT))
            response = await runtime.fill_model.ainvoke(messages)
            chunks.append(str(response.content or ""))
            break

        response = await runtime.evidence_model_ssh.ainvoke(messages)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            chunks.append(str(response.content or ""))
            break

        tool_messages = await runtime._execute_tool_calls(
            tool_calls,
            framework_id=evidence_fw,
            req_id=evidence_req,
            store=store,
        )
        messages.extend(tool_messages)
        for tm in tool_messages:
            tool_idx += 1
            text = str(tm.content or "")
            raw[f"tool_{tool_idx}_{tm.name or 'ssh'}"] = text
            chunks.append(f"[{tm.name}] {text}")

    evidence = "\n---\n".join(c.strip() for c in chunks if c and c.strip())
    evidence = truncate_text(
        evidence,
        runtime.settings.max_tool_output_chars * 2,
        "host_facts_evidence",
    )
    return await runtime._facts_from_host_facts_evidence(
        evidence=evidence,
        raw=raw,
        ssh_host=ssh_host,
        source="llm",
    )


async def facts_from_host_facts_evidence(
    runtime: AuditRuntime,
    *,
    evidence: str,
    raw: dict[str, str],
    ssh_host: str,
    source: str,
) -> HostFacts:
    """JSON-fill ``HostFacts`` from checklist / tool evidence."""
    fill_messages = [
        SystemMessage(content=HOST_FACTS_FILL_SYSTEM_PROMPT),
        HumanMessage(
            content=HOST_FACTS_FILL_PROMPT.format(
                ssh_host=ssh_host or "(unknown)",
                evidence=evidence or "(no evidence collected)",
            )
        ),
    ]
    try:
        fill_response = await runtime.fill_model.ainvoke(fill_messages)
        payload = _extract_json(str(fill_response.content or ""))
    except Exception as exc:  # noqa: BLE001
        payload = {"error": f"{type(exc).__name__}: {exc}"}

    facts = parse_host_facts_json(payload, ssh_host=ssh_host, raw=raw)
    facts = merge_facts_from_raw(facts, raw)
    if not facts.ssh_host:
        facts.ssh_host = ssh_host
    if not facts.collected_at:
        from datetime import datetime, timezone

        facts.collected_at = datetime.now(timezone.utc).isoformat()
    facts.raw["host_facts_source"] = source
    return facts


async def discover_inventory_hosts(
    runtime: AuditRuntime,
    *,
    intake: dict[str, Any],
    store: EvidenceStore,
) -> list[tuple[InventorySshTarget, HostFacts]]:
    """SSH-discover every inventory host for inventory-only flow."""
    slug = str(intake.get("client_slug") or client_slug(str(intake.get("client_name") or "")))
    targets = list_client_ssh_targets(runtime.settings.inventory_dir, slug)
    effective = effective_settings(runtime.settings)
    if not targets and effective.ssh_host:
        targets = [
            InventorySshTarget(
                host=effective.ssh_host,
                port=str(effective.ssh_port or 22),
                user=effective.ssh_user or "",
                password=effective.ssh_password or "",
                private_key_path=effective.ssh_private_key_path or "",
            )
        ]
    discovered: list[tuple[InventorySshTarget, HostFacts]] = []
    for target in targets:
        with runtime._target_scope(client_slug=slug, ssh_target=target, intake=intake):
            facts = await runtime._collect_host_facts(
                store=store,
                host_id=target.slug,
                user_request=str(intake.get("client_name") or ""),
            )
            # Optional LLM routing hints from collected software signals.
            try:
                route = await runtime._llm_route_frameworks_from_software(facts)
            except Exception as exc:  # noqa: BLE001
                route = {
                    "framework_ids": [],
                    "highlight_packages": [],
                    "highlight_binaries": list(facts.binaries or [])[:20],
                    "notes": f"route_error: {type(exc).__name__}: {exc}",
                }
            facts.raw["software_route"] = str(route)
            facts.raw["software_inventory_source"] = "llm"
        facts.ssh_host = target.host
        # Stash LLM routing on facts.raw for proposed_jobs builder.
        facts.raw["_llm_framework_ids"] = ",".join(route.get("framework_ids") or [])
        facts.raw["_llm_highlight_packages"] = "\n".join(route.get("highlight_packages") or [])
        facts.raw["_llm_highlight_binaries"] = "\n".join(route.get("highlight_binaries") or [])
        facts.raw["_llm_software_notes"] = str(route.get("notes") or "")
        host_base = store.host_root(target.slug)
        write_host_facts_json(host_base / "host_facts.json", facts, [])
        md = format_host_facts_markdown(facts, None, language="en")
        (host_base / "host_facts.md").write_text(md, encoding="utf-8")
        if facts.packages:
            (host_base / "packages_full.txt").write_text(
                "\n".join(facts.packages) + "\n",
                encoding="utf-8",
            )
        discovered.append((target, facts))
    return discovered


async def llm_route_frameworks_from_software(
    runtime: AuditRuntime,
    facts: HostFacts,
) -> dict[str, Any]:
    """Ask the LLM which agents/ frameworks match collected software signals.

    Args:
        facts: Host facts including binaries/packages from LLM discovery.

    Returns:
        Dict with ``framework_ids``, ``highlight_packages``,
        ``highlight_binaries``, ``notes`` (empty lists on failure).
    """
    known = {fw.id for fw in list_frameworks(runtime.settings.agents_dir)}
    pkg_lines = "\n".join(f"PKG:{p}" for p in (facts.packages or []))
    bin_lines = "\n".join(f"BIN:{b}" for b in (facts.binaries or []))
    file_lines = "\n".join(f"FILE:{f}" for f in (facts.key_files or []))
    inventory = "\n".join(x for x in (bin_lines, file_lines, pkg_lines) if x) or "(empty inventory)"
    # Keep routing prompt small — full dumps belong on disk, not in the LLM.
    inventory = truncate_text(
        inventory,
        min(runtime.settings.max_tool_output_chars * 4, 24_000),
        "software_inventory",
    )
    os_line = facts.os_pretty_name or f"{facts.os_id} {facts.os_version_id}".strip() or "unknown"
    messages = [
        SystemMessage(content=SOFTWARE_FRAMEWORK_ROUTE_SYSTEM),
        HumanMessage(
            content=SOFTWARE_FRAMEWORK_ROUTE_PROMPT.format(
                ssh_host=facts.ssh_host or "(unknown)",
                os_line=os_line,
                framework_catalog=frameworks_detect_catalog_text(runtime.settings.agents_dir),
                software_inventory=inventory,
            )
        ),
    ]
    try:
        response = await runtime.fill_model.ainvoke(messages)
        payload = _extract_json(str(response.content or "")) or {}
    except Exception as exc:  # noqa: BLE001
        return {
            "framework_ids": [],
            "highlight_packages": [],
            "highlight_binaries": [],
            "notes": f"LLM software routing failed: {type(exc).__name__}: {exc}",
        }
    ids = [str(x).strip() for x in (payload.get("framework_ids") or []) if str(x).strip() in known]
    highlights = [
        str(x).strip() for x in (payload.get("highlight_packages") or []) if str(x).strip()
    ][:40]
    hl_bins = [str(x).strip() for x in (payload.get("highlight_binaries") or []) if str(x).strip()][
        :40
    ]
    return {
        "framework_ids": ids,
        "highlight_packages": highlights,
        "highlight_binaries": hl_bins,
        "notes": str(payload.get("notes") or "").strip()[:500],
    }

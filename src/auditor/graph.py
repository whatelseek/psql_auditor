"""LangGraph cyclic auditor: route → assess → reconnect / HITL → finalize.

Drop-in frameworks live in ``agents/*.md``. The operator request selects one.

Control flow::

    START
      → route_framework → load_framework → assess_parallel
      → route_after_assess
           ├─ recoverable errors & retries left → reconnect_session ─┐
           │                                                         │
           │◄────────────────────────────────────────────────────────┘
           ├─ failed REQs (HITL) → human_gate  (LangGraph interrupt)
           │         ├─ retry → assess_parallel
           │         ├─ more failures → human_gate
           │         └─ done → finalize → END
           └─ else → finalize → END

``human_gate`` asks the operator to **skip** or **retry** via Open WebUI chat.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from pathlib import Path
from typing import Any, Literal

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langgraph.types import Command, interrupt

from auditor.access_probe import probe_access_services
from auditor.adhoc import run_adhoc_commands
from auditor.benchmark_store import BenchmarkStore
from auditor.checklist import Requirement
from auditor.compliance import format_compliance_markdown
from auditor.config import Settings, get_settings
from auditor.context import (
    compact_findings_for_summary,
    count_tool_rounds,
    truncate_text,
)
from auditor.followup import (
    followup_footer,
    run_refill_finding,
    run_revise_req,
    run_update_report,
)
from auditor.evidence_store import EvidenceStore, client_artifacts_id, new_run_id
from auditor.frameworks import (
    frameworks_catalog_text,
    get_framework,
    load_framework_checklist,
    route_framework,
    route_frameworks,
    select_frameworks_for_host,
)
from auditor.host_facts import (
    HostFacts,
    collect_host_facts_ssh,
    compare_to_netbox,
    format_host_facts_markdown,
    resolve_client_inventory,
    upsert_inventory_md,
    write_host_facts_json,
)
from auditor.hitl import (
    build_hitl_prompt,
    format_hitl_assistant_message,
    interrupt_payload_to_prompt,
    parse_hitl_decision,
)
from auditor.intake import (
    client_slug,
    domains_for_audit_type,
    format_intake_assistant_message,
    frameworks_for_audit_type,
    intake_interrupt_payload,
    parse_audit_type,
    parse_client_name,
    parse_yes_no,
    prompts_for_language,
    summarize_access_probe,
    summarize_cmdb_capabilities,
)
from auditor.language import (
    ReportLanguage,
    detect_report_language,
    language_instruction,
    language_name,
)
from auditor.memory.playbook_store import PlaybookMemory
from auditor.report_archive import package_and_publish_archive
from auditor.llm import build_chat_model
from auditor.prompts import (
    EVIDENCE_FORCE_PROMPT,
    EVIDENCE_PROMPT,
    EVIDENCE_SYSTEM_PROMPT,
    FILL_CELL_PROMPT,
    FILL_SYSTEM_PROMPT,
    FINALIZE_PROMPT,
)
from auditor.secrets_file import (
    InventorySshTarget,
    bind_ssh_target,
    list_client_ssh_targets,
    load_inventory_credentials,
)
from auditor.state import AuditorState, Finding, render_report
from auditor.tools.mcp_client import get_mcp_tools, reconnect_mcp_session
from auditor.tools.netbox_mcp import (
    fetch_netbox_device_by_name,
    get_netbox_tools,
    probe_netbox_capabilities,
)
from auditor.tools.ssh import get_ssh_tools

# Tight markers only — bare "session" / "timeout" / "eof" caused false reconnects.
_RECOVERABLE_MARKERS = (
    "mcp error",
    "mcp reconnect failed",
    "ssh error",
    "connection refused",
    "connection reset",
    "broken pipe",
    "not connected",
    "closed resource",
    "connection closed",
)


def _all_tools(*, has_cmdb: bool = True) -> list:
    """SSH + Postgres MCP tools; NetBox only when CMDB is in scope."""
    tools = [*get_ssh_tools(), *get_mcp_tools()]
    if has_cmdb:
        tools.extend(get_netbox_tools())
    return tools


def _extract_json(text: str) -> dict[str, Any] | None:
    text = text.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def _normalize_status(value: str | None) -> str:
    allowed = {"pass", "fail", "partial", "error", "skipped"}
    status = (value or "error").strip().lower()
    return status if status in allowed else "error"


def _is_recoverable_finding(finding: Finding) -> bool:
    """True when a finding looks like a dead session / transport failure."""
    if finding.status != "error":
        return False
    blob = f"{finding.evidence} {finding.notes}".lower()
    return any(marker in blob for marker in _RECOVERABLE_MARKERS)


def _as_finding(value: Finding | dict[str, Any]) -> Finding:
    return value if isinstance(value, Finding) else Finding.model_validate(value)


def _hitl_candidates(state: AuditorState) -> list[str]:
    """Requirement ids with ``status=error`` not yet skipped by the operator."""
    findings = state.get("findings") or {}
    skipped = set(state.get("hitl_skipped") or [])
    out: list[str] = []
    for req_id, raw in findings.items():
        finding = _as_finding(raw)
        if finding.status == "error" and req_id not in skipped:
            out.append(req_id)
    return sorted(out)


def _tool_result_looks_failed(text: str) -> bool:
    """True when a tool result string indicates transport/auth failure."""
    lower = (text or "").lower()
    return any(
        marker in lower
        for marker in (
            "ssh error",
            "mcp error",
            "tool error",
            "connection refused",
            "permission denied",
        )
    )


class AuditorGraph:
    """Compile and run the cyclic multi-framework audit StateGraph."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        # Full tool set registered; NetBox calls are blocked when has_cmdb=false.
        self.tools = _all_tools(has_cmdb=True)
        self.tools_by_name = {t.name: t for t in self.tools}
        self._tools_no_netbox = _all_tools(has_cmdb=False)
        # Evidence stores keyed by run_id (safe for parallel multi-framework).
        self._evidence_by_run: dict[str, EvidenceStore] = {}
        # Multi-framework orchestration while a HITL pause is active.
        self._multi_sessions: dict[str, dict[str, Any]] = {}
        self._checkpointer = MemorySaver()
        # Long-term procedural memory (framework command playbooks).
        self.playbooks = (
            PlaybookMemory(
                playbooks_dir=self.settings.playbooks_dir,
                memory_dir=self.settings.memory_dir,
                learn=self.settings.memory_learn,
            )
            if self.settings.memory_enabled
            else None
        )
        self.evidence_model = build_chat_model(self.settings).bind_tools(self.tools)
        self.evidence_model_no_netbox = build_chat_model(self.settings).bind_tools(
            self._tools_no_netbox
        )
        self.fill_model = build_chat_model(self.settings)
        self.benchmark = (
            BenchmarkStore(self.settings.resolve_benchmark_path())
            if self.settings.benchmark_enabled
            else None
        )
        if self.benchmark is not None:
            self.benchmark.ensure_file()
        self.graph = self._build()
        self.intake_graph = self._build_intake()

    def _evidence_llm(self, *, has_cmdb: bool):
        return self.evidence_model if has_cmdb else self.evidence_model_no_netbox

    def _build(self):
        graph = StateGraph(AuditorState)
        graph.add_node("route_framework", self.route_framework_node)
        graph.add_node("load_framework", self.load_framework)
        graph.add_node("collect_host_facts", self.collect_host_facts)
        graph.add_node("assess_parallel", self.assess_parallel)
        graph.add_node("reconnect_session", self.reconnect_session)
        graph.add_node("human_gate", self.human_gate)
        graph.add_node("finalize", self.finalize)

        graph.add_edge(START, "route_framework")
        graph.add_edge("route_framework", "load_framework")
        graph.add_edge("load_framework", "collect_host_facts")
        graph.add_edge("collect_host_facts", "assess_parallel")
        graph.add_conditional_edges(
            "assess_parallel",
            self.route_after_assess,
            {
                "reconnect_session": "reconnect_session",
                "human_gate": "human_gate",
                "finalize": "finalize",
            },
        )
        # Cycle: after reconnect, re-run assess on remaining pending_ids only.
        graph.add_edge("reconnect_session", "assess_parallel")
        graph.add_conditional_edges(
            "human_gate",
            self.route_after_hitl,
            {
                "assess_parallel": "assess_parallel",
                "human_gate": "human_gate",
                "finalize": "finalize",
            },
        )
        graph.add_edge("finalize", END)
        return graph.compile(checkpointer=self._checkpointer)

    def _build_intake(self):
        graph = StateGraph(AuditorState)
        graph.add_node("intake_gate", self.intake_gate)
        graph.add_edge(START, "intake_gate")
        graph.add_edge("intake_gate", END)
        return graph.compile(checkpointer=self._checkpointer)

    async def intake_gate(self, state: AuditorState) -> dict[str, Any]:
        """Multi-step pre-audit questionnaire via successive interrupts."""
        if not self.settings.intake_enabled or state.get("intake_complete"):
            return {"intake_complete": True}

        lang = self._report_language(state)
        prompts = prompts_for_language(lang.code)
        intake: dict[str, Any] = dict(state.get("intake") or {})

        # 1) Client name
        while not intake.get("client_name"):
            raw = interrupt(
                intake_interrupt_payload(step="client_name", prompt=prompts.client)
            )
            name = parse_client_name(str(raw or ""))
            if name:
                intake["client_name"] = name
                intake["client_slug"] = client_slug(name)
                from auditor.host_facts import resolve_client_dir

                client_dir = resolve_client_dir(
                    Path(self.settings.inventory_dir),
                    intake["client_slug"],
                    display_name=name,
                )
                # Artifacts folder = inventory client folder name (e.g. TestCompany).
                if not client_dir.is_dir():
                    client_dir = (
                        Path(self.settings.inventory_dir) / client_artifacts_id(name)
                    )
                client_dir.mkdir(parents=True, exist_ok=True)
                artifacts_id = client_dir.name
                store = self._store_from_state(state)
                if store is not None:
                    old_id = store.run_id
                    store.rebind_run_id(artifacts_id)
                    self._evidence_by_run.pop(old_id, None)
                    self._evidence_by_run[store.run_id] = store
                    # Keep temp id as alias until intake state is rewritten.
                    self._evidence_by_run[old_id] = store
                    for sess in self._multi_sessions.values():
                        if sess.get("run_id") == old_id:
                            sess["run_id"] = store.run_id
                    intake["artifacts_run_id"] = store.run_id
                    # Patch live state keys for the rest of this node.
                    state["evidence_run_id"] = store.run_id  # type: ignore[typeddict-item]
                    state["evidence_run_dir"] = str(store.root)  # type: ignore[typeddict-item]

                applied = load_inventory_credentials(
                    self.settings.inventory_dir,
                    intake["client_slug"],
                    override_existing=True,
                )
                intake["credentials_loaded"] = sorted(applied.keys())
                get_settings.cache_clear()
                self.settings = get_settings()
                break
            prompts = prompts_for_language(lang.code)
            prompts = type(prompts)(
                client=prompts.client
                + (
                    "\n\n_Please reply with a non-empty client name._"
                    if lang.code == "en"
                    else "\n\n_Укажите непустое название клиента._"
                ),
                cmdb=prompts.cmdb,
                access=prompts.access,
                audit_type=prompts.audit_type,
            )

        # 2) CMDB / NetBox
        while "has_cmdb" not in intake:
            raw = interrupt(
                intake_interrupt_payload(step="cmdb", prompt=prompts.cmdb)
            )
            yn = parse_yes_no(str(raw or ""))
            if yn == "unknown":
                continue
            intake["has_cmdb"] = yn == "yes"
            if yn == "yes":
                probe = await probe_netbox_capabilities(self.settings)
                intake["cmdb_probe"] = probe
                intake["inventory_scope"] = ""
                intake["inventory_found"] = False
                intake["inventory_path"] = ""
            else:
                inv_path, scope, found = resolve_client_inventory(
                    Path(self.settings.inventory_dir),
                    str(intake.get("client_slug") or ""),
                )
                intake["cmdb_probe"] = {
                    "reachable": False,
                    "error": "operator reported no CMDB",
                    "fields": {},
                }
                intake["inventory_scope"] = scope
                intake["inventory_found"] = found
                intake["inventory_path"] = str(inv_path) if inv_path else ""

        # 3) Access — only after checking client inventory folder when no CMDB
        cmdb_summary = summarize_cmdb_capabilities(
            intake.get("cmdb_probe") or {}, language=lang.code
        )
        cred_keys = intake.get("credentials_loaded") or []
        if lang.code.startswith("ru"):
            cred_line = (
                f"**Учётные данные загружены из inventory** ({len(cred_keys)} ключей): "
                + (", ".join(cred_keys) if cred_keys else "нет — добавьте таблицу Credentials в INVENTORY.md")
            )
        else:
            cred_line = (
                f"**Credentials loaded from inventory** ({len(cred_keys)} keys): "
                + (", ".join(cred_keys) if cred_keys else "none — add a Credentials table to INVENTORY.md")
            )
        if not intake.get("has_cmdb"):
            found = bool(intake.get("inventory_found"))
            inv_path = intake.get("inventory_path") or ""
            if lang.code.startswith("ru"):
                status = (
                    f"**Инвентарь найден:** `{inv_path}`"
                    if found
                    else f"**Инвентарь не найден** по пути `{inv_path}`"
                )
            else:
                status = (
                    f"**Inventory found:** `{inv_path}`"
                    if found
                    else f"**Inventory not found** at `{inv_path}`"
                )
            scope_block = (
                f"\n\n### Client inventory check\n\n{status}\n\n{cred_line}\n\n"
                + str(intake.get("inventory_scope") or "")[:4000]
            )
        else:
            scope_block = f"\n\n{cred_line}\n"
        access_prompt = f"{prompts.access}\n\n{cmdb_summary}{scope_block}"
        while "has_access" not in intake:
            raw = interrupt(
                intake_interrupt_payload(step="access", prompt=access_prompt)
            )
            yn = parse_yes_no(str(raw or ""))
            if yn == "unknown":
                continue
            intake["has_access"] = yn == "yes"
            if yn == "yes":
                access = await probe_access_services(self.settings)
                intake["access_probe"] = access
            else:
                intake["access_probe"] = {
                    "services": [],
                    "any_ok": False,
                    "skipped": True,
                }

        access_summary = summarize_access_probe(
            intake.get("access_probe") or {}, language=lang.code
        )
        audit_prompt = f"{prompts.audit_type}\n\n{access_summary}"
        while not intake.get("audit_types"):
            raw = interrupt(
                intake_interrupt_payload(step="audit_type", prompt=audit_prompt)
            )
            atype = parse_audit_type(str(raw or ""))
            if atype:
                intake["audit_types"] = atype
                break

        store = self._store_from_state(state)
        if store is not None:
            store.write_run_meta(
                intake_complete=True,
                intake=intake,
                client_name=intake.get("client_name"),
                has_cmdb=intake.get("has_cmdb"),
                has_access=intake.get("has_access"),
                audit_types=intake.get("audit_types"),
            )

        out: dict[str, Any] = {
            "intake_complete": True,
            "intake": intake,
            "client_name": str(intake.get("client_name") or ""),
            "has_cmdb": bool(intake.get("has_cmdb")),
            "has_access": bool(intake.get("has_access")),
            "audit_types": str(intake.get("audit_types") or "both"),
            "messages": [
                AIMessage(
                    content=(
                        f"Intake complete for **{intake.get('client_name')}**. "
                        f"Audit type: `{intake.get('audit_types')}`. Starting assessment…"
                    ),
                    name="auditor",
                )
            ],
        }
        if store is not None:
            out["evidence_run_id"] = store.run_id
            out["evidence_run_dir"] = str(store.root)
        return out

    async def collect_host_facts(self, state: AuditorState) -> dict[str, Any]:
        """Gather hostname/OS/software/disk/RAM/CPU; compare NetBox; refresh INVENTORY.md."""
        if state.get("error") and not (state.get("requirements") or {}):
            return {}

        intake = dict(state.get("intake") or {})
        has_access = bool(state.get("has_access") or intake.get("has_access"))
        has_cmdb = bool(state.get("has_cmdb") or intake.get("has_cmdb"))
        client_name = str(
            state.get("client_name") or intake.get("client_name") or "client"
        )
        host_id = str(state.get("evidence_host_id") or "").strip()
        lang = self._report_language(state)
        facts_md = ""
        drift_md = ""
        drift_items = []
        facts = None

        if has_access and self.settings.ssh_host:
            facts = await collect_host_facts_ssh()
            nb_device = None
            if has_cmdb and facts.hostname and not facts.error:
                nb_device = await fetch_netbox_device_by_name(
                    facts.hostname, self.settings
                )
            if has_cmdb:
                drift_items = compare_to_netbox(facts, nb_device)
            facts_md = format_host_facts_markdown(
                facts, drift_items if has_cmdb else None, language=lang.code
            )
            drift_md = ""
            if has_cmdb and drift_items:
                # Already embedded in facts_md; keep a short flag for meta
                drift_md = facts_md

            store = self._store_from_state(state)
            if store is not None and facts is not None:
                if host_id:
                    store.host_segment = host_id
                facts_base = store.host_root(host_id or None)
                write_host_facts_json(
                    facts_base / "host_facts.json", facts, drift_items
                )
                (facts_base / "host_facts.md").write_text(facts_md, encoding="utf-8")

            if not has_cmdb and facts is not None:
                inv_path = (
                    Path(self.settings.inventory_dir)
                    / client_slug(client_name)
                    / "INVENTORY.md"
                )
                upsert_inventory_md(
                    inv_path,
                    client_name=client_name,
                    facts=facts,
                    scope_text=str(intake.get("inventory_scope") or ""),
                    reachable_services=(intake.get("access_probe") or {}).get(
                        "services"
                    ),
                )
                if store is not None:
                    dest = store.root / "INVENTORY.md"
                    dest.write_text(inv_path.read_text(encoding="utf-8"), encoding="utf-8")
        elif not has_cmdb:
            # Still materialize inventory from scope when no live access
            inv_path = (
                Path(self.settings.inventory_dir)
                / client_slug(client_name)
                / "INVENTORY.md"
            )
            upsert_inventory_md(
                inv_path,
                client_name=client_name,
                facts=None,
                scope_text=str(intake.get("inventory_scope") or ""),
                reachable_services=(intake.get("access_probe") or {}).get("services"),
            )
            store = self._store_from_state(state)
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

    async def route_framework_node(self, state: AuditorState) -> dict[str, Any]:
        """Node: choose ``agents/<framework>.md`` (honors pinned ``framework_id``)."""
        user_request = state.get("user_request") or ""
        if not user_request:
            for msg in reversed(state.get("messages") or []):
                if isinstance(msg, HumanMessage):
                    user_request = str(msg.content)
                    break
        user_request = truncate_text(
            user_request,
            self.settings.max_user_request_chars,
            "user_request",
        )
        report_lang = detect_report_language(user_request)

        pinned = state.get("framework_id") or ""
        try:
            if pinned:
                fw = get_framework(pinned, self.settings.agents_dir)
                if fw is None:
                    raise FileNotFoundError(
                        f"Pinned framework `{pinned}` not found in agents/"
                    )
            else:
                fw = route_framework(user_request, self.settings.agents_dir)
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

        catalog = frameworks_catalog_text(self.settings.agents_dir)
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

    async def load_framework(self, state: AuditorState) -> dict[str, Any]:
        """Node: load the drop-in Markdown checklist for the selected framework."""
        if state.get("error") and not state.get("framework_id"):
            return {"pending_ids": [], "requirements": {}}

        selected = get_framework(
            state.get("framework_id") or "",
            self.settings.agents_dir,
        )
        if selected is None:
            # Fallback: route again from user text.
            selected = route_framework(
                state.get("user_request") or "",
                self.settings.agents_dir,
            )
        checklist = load_framework_checklist(selected)
        req_map = checklist.by_id()
        return {
            "framework_id": selected.id,
            "framework_title": selected.title,
            "checklist_title": checklist.title,
            "requirements": req_map,
            "pending_ids": checklist.ids(),
            "findings": {},
            "report": "",
            "messages": [
                AIMessage(
                    content=(
                        f"Loaded {len(req_map)} requirements from "
                        f"{selected.path}"
                    ),
                    name="auditor",
                )
            ],
        }

    async def assess_parallel(self, state: AuditorState) -> dict[str, Any]:
        """Node: fill report cells for pending requirements (parallel)."""
        requirements = state.get("requirements") or {}
        pending = list(state.get("pending_ids") or [])
        if not pending:
            return {
                "pending_ids": [],
                "messages": [
                    AIMessage(content="No pending requirements to assess.", name="auditor")
                ],
            }

        user_request = state.get("user_request") or "(none)"
        framework_id = state.get("framework_id") or ""
        report_lang = self._report_language(state, user_request)
        store = self._store_from_state(state)
        host_id = str(state.get("evidence_host_id") or "").strip()
        if store is not None and host_id:
            store.host_segment = host_id
        has_cmdb = bool(state.get("has_cmdb") or (state.get("intake") or {}).get("has_cmdb"))
        limit = max(1, self.settings.max_parallel_assessments)
        sem = asyncio.Semaphore(limit)

        async def _worker(req_id: str) -> Finding:
            async with sem:
                try:
                    special = self._deterministic_it_audit_finding(
                        req_id=req_id,
                        requirement=requirements[req_id],
                        framework_id=framework_id,
                        state=state,
                        store=store,
                    )
                    if special is not None:
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
                            store.write_finding(
                                framework_id, req_id, special.model_dump()
                            )
                        return special
                    return await self._fill_requirement_cells(
                        req_id=req_id,
                        requirement=requirements[req_id],
                        user_request=user_request,
                        framework_id=framework_id,
                        store=store,
                        report_language=report_lang,
                        has_cmdb=has_cmdb,
                    )
                except Exception as exc:  # noqa: BLE001
                    req = requirements.get(req_id)
                    finding = Finding(
                        requirement_id=req_id,
                        title=req.title if req else "",
                        status="error",
                        severity=req.severity if req else "",
                        category=req.category if req else "",
                        pass_criteria=req.pass_criteria if req else "",
                        evidence=f"Cell fill failed: {type(exc).__name__}: {exc}",
                        remediation="Retry after restoring SSH/MCP session",
                    )
                    if store is not None:
                        store.write_finding(
                            framework_id,
                            req_id,
                            finding.model_dump(),
                        )
                    return finding

        work_ids = [rid for rid in pending if rid in requirements]
        findings_list = await asyncio.gather(*[_worker(rid) for rid in work_ids])
        new_findings = {f.requirement_id: f for f in findings_list}

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

    def route_after_assess(
        self, state: AuditorState
    ) -> Literal["reconnect_session", "human_gate", "finalize"]:
        """Reconnect on transport errors; otherwise ask the human about failures."""
        pending = state.get("pending_ids") or []
        retry_count = int(state.get("retry_count") or 0)
        max_retries = self.settings.max_session_retries
        if pending and retry_count < max_retries:
            return "reconnect_session"
        if self.settings.hitl_enabled and _hitl_candidates(state):
            return "human_gate"
        return "finalize"

    def route_after_hitl(
        self, state: AuditorState
    ) -> Literal["assess_parallel", "human_gate", "finalize"]:
        """After skip/retry: reassess, ask about the next failure, or finalize."""
        pending = state.get("pending_ids") or []
        if pending:
            return "assess_parallel"
        if self.settings.hitl_enabled and _hitl_candidates(state):
            return "human_gate"
        return "finalize"

    async def reconnect_session(self, state: AuditorState) -> dict[str, Any]:
        """Node: restore MCP session and bump retry counter (graph cycle)."""
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

    async def human_gate(self, state: AuditorState) -> dict[str, Any]:
        """Pause for the operator when a requirement could not be audited.

        Uses LangGraph ``interrupt()``. The OpenAI-compatible API resumes with
        ``Command(resume=user_text)`` when the user replies skip/retry.
        """
        candidates = _hitl_candidates(state)
        if not candidates:
            return {"awaiting_hitl": False, "pending_ids": []}

        requirements = state.get("requirements") or {}
        findings = state.get("findings") or {}
        framework_id = state.get("framework_id") or ""
        store = self._store_from_state(state)

        req_id = candidates[0]
        finding = _as_finding(findings[req_id])
        requirement = requirements.get(req_id) or Requirement(
            id=req_id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            pass_criteria=finding.pass_criteria,
        )
        evidence_dir = None
        if store is not None:
            evidence_dir = str(store.requirement_dir(framework_id, req_id))

        prompt = build_hitl_prompt(
            framework_id=framework_id,
            requirement=requirement,
            finding=finding,
            evidence_dir=evidence_dir,
        )
        payload: dict[str, Any] = {
            "type": "skip_or_retry",
            "requirement_id": req_id,
            "framework_id": framework_id,
            "candidates": candidates,
            "prompt": prompt,
        }

        decision = parse_hitl_decision(interrupt(payload))
        while decision.action == "unknown":
            retry_prompt = (
                "I didn't understand that reply.\n\n"
                "Please answer with **skip**, **retry**, **skip all**, or **retry all**.\n\n"
                f"{prompt}"
            )
            decision = parse_hitl_decision(
                interrupt({**payload, "prompt": retry_prompt})
            )

        skipped = list(state.get("hitl_skipped") or [])

        if decision.action == "skip_all":
            updates: dict[str, Finding] = {}
            for rid in candidates:
                updates[rid] = self._skipped_finding(
                    _as_finding(findings[rid]),
                    reason="Skipped by operator (skip all).",
                )
                if rid not in skipped:
                    skipped.append(rid)
            return {
                "findings": updates,
                "hitl_skipped": skipped,
                "pending_ids": [],
                "awaiting_hitl": False,
                "messages": [
                    AIMessage(
                        content=(
                            f"Operator skipped {len(candidates)} failed requirement(s)."
                        ),
                        name="auditor",
                    )
                ],
            }

        if decision.action == "retry_all":
            return {
                "pending_ids": list(candidates),
                "retry_count": 0,
                "awaiting_hitl": False,
                "messages": [
                    AIMessage(
                        content=(
                            f"Operator requested retry for {len(candidates)} "
                            "failed requirement(s)."
                        ),
                        name="auditor",
                    )
                ],
            }

        if decision.action == "skip":
            if req_id not in skipped:
                skipped.append(req_id)
            return {
                "findings": {
                    req_id: self._skipped_finding(
                        finding,
                        reason="Skipped by operator after failed assessment.",
                    )
                },
                "hitl_skipped": skipped,
                "pending_ids": [],
                "awaiting_hitl": False,
                "messages": [
                    AIMessage(
                        content=f"Operator skipped `{req_id}`.",
                        name="auditor",
                    )
                ],
            }

        # retry single — reset session retry budget so reconnect can run again
        return {
            "pending_ids": [req_id],
            "retry_count": 0,
            "awaiting_hitl": False,
            "messages": [
                AIMessage(
                    content=f"Operator requested retry for `{req_id}`.",
                    name="auditor",
                )
            ],
        }

    def _deterministic_it_audit_finding(
        self,
        *,
        req_id: str,
        requirement: Requirement,
        framework_id: str,
        state: AuditorState,
        store: EvidenceStore | None,
    ) -> Finding | None:
        """Resolve IT-audit REQs that must not HITL-loop on missing NetBox.

        REQ-006 without CMDB: pass/fail on ``INVENTORY.md`` (never ``error``).
        REQ-007: summarize intake access probe (never call placeholder SSH).
        """
        if framework_id != "it_audit":
            return None
        intake = state.get("intake") or {}
        has_cmdb = bool(state.get("has_cmdb") or intake.get("has_cmdb"))

        if req_id == "REQ-006" and not has_cmdb:
            inv_path = store.root / "INVENTORY.md" if store is not None else None
            if inv_path is not None and inv_path.is_file():
                return Finding(
                    requirement_id=req_id,
                    title=requirement.title,
                    status="pass",
                    severity=requirement.severity,
                    category=requirement.category,
                    pass_criteria=requirement.pass_criteria,
                    evidence=(
                        "Operator reported no CMDB/NetBox. "
                        f"INVENTORY.md is present at `{inv_path}`."
                    ),
                    remediation="",
                    notes="Deterministic: skip NetBox when has_cmdb=false.",
                )
            return Finding(
                requirement_id=req_id,
                title=requirement.title,
                status="fail",
                severity=requirement.severity,
                category=requirement.category,
                pass_criteria=requirement.pass_criteria,
                evidence=(
                    "Operator reported no CMDB/NetBox, but INVENTORY.md is "
                    "missing from the evidence run directory."
                ),
                remediation=(
                    "Ensure intake wrote inventory/<client>/INVENTORY.md and "
                    "copied it into the artifacts run folder."
                ),
                notes="Deterministic: no NetBox; inventory file required.",
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
                remediation=""
                if any_ok
                else "Fix SSH/Postgres credentials in inventory and re-probe.",
                notes="Deterministic from intake access_probe.",
            )

        return None

    @staticmethod
    def _skipped_finding(finding: Finding, *, reason: str) -> Finding:
        """Mark a failed finding as skipped while preserving the failure why."""
        notes = finding.notes or ""
        if reason not in notes:
            notes = f"{notes}\n{reason}".strip()
        return finding.model_copy(
            update={
                "status": "skipped",
                "notes": notes,
                "remediation": finding.remediation
                or "Operator skipped this check; re-run later if needed.",
            }
        )

    def _store_from_state(self, state: AuditorState) -> EvidenceStore | None:
        """Resolve the evidence store for this graph run (if configured)."""
        run_id = state.get("evidence_run_id") or ""
        run_dir = state.get("evidence_run_dir") or ""
        if not run_id and not run_dir:
            return None
        if not run_id and run_dir:
            run_id = Path(run_dir).name
        if run_id in self._evidence_by_run:
            return self._evidence_by_run[run_id]
        store = EvidenceStore(self.settings.evidence_dir, run_id=run_id)
        if run_dir:
            path = Path(run_dir)
            if path.is_dir():
                store.root = path
                store.run_id = path.name
        self._evidence_by_run[store.run_id] = store
        return store

    async def _fill_requirement_cells(
        self,
        req_id: str,
        requirement: Requirement,
        user_request: str,
        framework_id: str,
        store: EvidenceStore | None = None,
        report_language: ReportLanguage | None = None,
        *,
        has_cmdb: bool = True,
    ) -> Finding:
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
        evidence = await self._gather_evidence(
            req_id,
            requirement,
            user_request,
            framework_id,
            store=store,
            has_cmdb=has_cmdb,
        )
        evidence = truncate_text(
            evidence,
            self.settings.max_tool_output_chars,
            "evidence",
        )
        report_lang = report_language or self._report_language_from_request(
            user_request
        )
        lang_instr = language_instruction(report_lang)
        fill_messages = [
            SystemMessage(
                content=FILL_SYSTEM_PROMPT.format(language_instruction=lang_instr)
            ),
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
        response = await self.fill_model.ainvoke(fill_messages)
        finding = self._cells_to_finding(req_id, requirement, response, evidence)
        if store is not None:
            store.write_finding(framework_id, req_id, finding.model_dump())
        return finding

    async def _gather_evidence(
        self,
        req_id: str,
        requirement: Requirement,
        user_request: str,
        framework_id: str,
        store: EvidenceStore | None = None,
        *,
        has_cmdb: bool = True,
    ) -> str:
        playbook_block = ""
        if self.playbooks is not None and self.settings.memory_enabled:
            playbook_block = self.playbooks.format_prompt_block(framework_id, req_id)
        cmdb_note = (
            "NetBox CMDB tools are available."
            if has_cmdb
            else "No CMDB — do not call NetBox tools; use inventory and SSH/Postgres only."
        )
        messages: list = [
            SystemMessage(
                content=(
                    f"{EVIDENCE_SYSTEM_PROMPT}\n\n"
                    f"Active framework: `{framework_id}`. "
                    f"{cmdb_note} "
                    "Use SSH and/or MCP tools appropriate for this framework."
                )
            ),
            HumanMessage(
                content=EVIDENCE_PROMPT.format(
                    user_request=user_request,
                    requirement_block=requirement.to_prompt_block(),
                    playbook_block=playbook_block
                    or "(no playbook memory for this requirement)",
                )
            ),
        ]
        chunks: list[str] = []
        max_rounds = self.settings.max_tool_rounds_per_item
        evidence_llm = self._evidence_llm(has_cmdb=has_cmdb)

        for _ in range(max_rounds + 1):
            rounds = count_tool_rounds(messages)
            if rounds >= max_rounds:
                messages.append(HumanMessage(content=EVIDENCE_FORCE_PROMPT))
                response = await self.fill_model.ainvoke(messages)
                chunks.append(str(response.content or ""))
                break

            response = await evidence_llm.ainvoke(messages)
            messages.append(response)
            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                chunks.append(str(response.content or ""))
                break

            tool_messages = await self._execute_tool_calls(
                tool_calls,
                framework_id=framework_id,
                req_id=req_id,
                store=store,
                has_cmdb=has_cmdb,
            )
            messages.extend(tool_messages)
            for tm in tool_messages:
                chunks.append(f"[{tm.name}] {tm.content}")

        return "\n---\n".join(c.strip() for c in chunks if c and c.strip())

    async def _execute_tool_calls(
        self,
        tool_calls: list[dict[str, Any]],
        *,
        framework_id: str = "",
        req_id: str = "",
        store: EvidenceStore | None = None,
        has_cmdb: bool = True,
    ) -> list[ToolMessage]:
        async def _one(tc: dict[str, Any]) -> ToolMessage:
            name = tc.get("name") or ""
            args = tc.get("args") or {}
            call_id = tc.get("id") or name
            error: str | None = None
            full_result = ""
            if not has_cmdb and name.startswith("netbox"):
                full_result = (
                    "Tool error: NetBox is disabled for this run "
                    "(operator reported no CMDB). Use inventory only."
                )
                error = full_result
                content = full_result
            else:
                tool = self.tools_by_name.get(name)
                if tool is None:
                    full_result = f"Tool error: unknown tool '{name}'"
                    error = full_result
                    content = full_result
                else:
                    try:
                        raw = await tool.ainvoke(args)
                        full_result = str(raw)
                        content = truncate_text(
                            full_result,
                            self.settings.max_tool_output_chars,
                            "tool",
                        )
                    except Exception as exc:  # noqa: BLE001
                        full_result = f"Tool error: {type(exc).__name__}: {exc}"
                        error = full_result
                        content = full_result
            if store is not None and req_id:
                store.write_tool_result(
                    framework_id,
                    req_id,
                    name,
                    args if isinstance(args, dict) else {"value": args},
                    full_result,
                    error=error,
                )
            # Long-term memory: remember successful recipes (hot path).
            if (
                self.playbooks is not None
                and self.settings.memory_learn
                and req_id
                and not error
                and not _tool_result_looks_failed(full_result)
            ):
                self.playbooks.remember_tool(
                    framework_id,
                    req_id,
                    name,
                    args if isinstance(args, dict) else {"value": args},
                    success=True,
                )
            return ToolMessage(content=content, tool_call_id=call_id, name=name)

        return list(await asyncio.gather(*[_one(tc) for tc in tool_calls]))

    def _cells_to_finding(
        self,
        req_id: str,
        req: Requirement,
        ai: AIMessage,
        fallback_evidence: str,
    ) -> Finding:
        data = _extract_json(str(ai.content or "")) or {}
        observation = str(
            data.get("observation")
            or data.get("evidence")
            or fallback_evidence
            or ai.content
            or ""
        )
        recommendation = str(
            data.get("recommendation") or data.get("remediation") or ""
        )
        # If observation still looks like a transport failure, force error status
        # so the cyclic reconnect path can pick it up.
        status = _normalize_status(data.get("status"))
        tmp = Finding(
            requirement_id=req_id,
            title=req.title,
            status=status,  # type: ignore[arg-type]
            severity=req.severity,
            category=req.category,
            pass_criteria=req.pass_criteria,
            evidence=observation,
            remediation=recommendation,
            notes=str(data.get("notes") or ""),
        )
        # Transport failures must stay status=error so reconnect / HITL can fire,
        # even when the model incorrectly marks the cell as pass/fail/partial.
        if status != "error" and _is_recoverable_finding(
            Finding(
                requirement_id=req_id,
                status="error",
                evidence=observation,
                notes=str(data.get("notes") or ""),
            )
        ):
            tmp.status = "error"
        tmp.evidence = truncate_text(
            tmp.evidence or "",
            self.settings.max_finding_evidence_chars,
            "observation",
        )
        tmp.remediation = truncate_text(
            tmp.remediation or "",
            min(self.settings.max_finding_evidence_chars, 1200),
            "recommendation",
        )
        return tmp

    def _report_language(
        self, state: AuditorState | None = None, user_request: str = ""
    ) -> ReportLanguage:
        code = ""
        if state:
            code = str(state.get("report_language") or "").strip()
        if code:
            return ReportLanguage(code=code, name=language_name(code))
        text = user_request or (state.get("user_request") if state else "") or ""
        return detect_report_language(text)

    def _report_language_from_request(self, user_request: str) -> ReportLanguage:
        return detect_report_language(user_request)

    async def finalize(self, state: AuditorState) -> dict[str, Any]:
        """Assemble fixed report + short executive summary."""
        if state.get("error") and not (state.get("requirements") or {}):
            msg = state.get("error") or "No framework available."
            return {
                "report": msg,
                "messages": [
                    RemoveMessage(id=REMOVE_ALL_MESSAGES),
                    AIMessage(content=msg),
                ],
            }

        findings = state.get("findings") or {}
        requirements = state.get("requirements") or {}
        title = (
            state.get("checklist_title")
            or state.get("framework_title")
            or "Security Audit"
        )
        report_lang = self._report_language(state)
        lang_instr = language_instruction(report_lang)
        full_report = render_report(
            title, findings, requirements, language=report_lang
        )
        digest = compact_findings_for_summary(
            findings,
            evidence_chars=self.settings.max_finalize_evidence_chars,
        )
        try:
            response = await self.fill_model.ainvoke(
                [
                    SystemMessage(
                        content=(
                            "You write short executive summaries for fixed-format "
                            "security audit reports across OS/DB frameworks. "
                            f"{lang_instr}"
                        )
                    ),
                    HumanMessage(
                        content=FINALIZE_PROMPT.format(
                            report=digest,
                            report_language=report_lang.name,
                            language_instruction=lang_instr,
                        )
                    ),
                ]
            )
            summary = str(response.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            summary = f"(Summary generation failed: {exc})"

        fw = state.get("framework_id") or ""
        retries = int(state.get("retry_count") or 0)
        store = self._store_from_state(state)
        evidence_note = ""
        if store is not None:
            host_id = str(state.get("evidence_host_id") or "").strip()
            if host_id:
                store.host_segment = host_id
            store.write_report(fw or "framework", f"{summary}\n\n---\n\n{full_report}")
            evidence_note = f" | evidence: `{store.root}`"

        if self.benchmark is not None and findings and fw:
            try:
                evidence_rel = ""
                if store is not None:
                    try:
                        evidence_rel = str(
                            store.root.relative_to(Path(self.settings.evidence_dir).resolve())
                        )
                    except ValueError:
                        evidence_rel = str(store.root)
                self.benchmark.append_from_findings(
                    run_id=state.get("evidence_run_id") or (store.run_id if store else ""),
                    framework_id=fw,
                    findings=findings,
                    evidence_relpath=evidence_rel,
                )
            except Exception:  # noqa: BLE001
                pass

        header = (
            f"Framework: `{fw}` | session reconnects: {retries}{evidence_note}\n\n"
        )
        client = state.get("client_name") or ""
        if client:
            header = f"Client: **{client}** | {header}"
        preamble_parts: list[str] = []
        if state.get("host_facts_md"):
            preamble_parts.append(str(state.get("host_facts_md")))
        preamble = ("\n".join(preamble_parts) + "\n\n---\n\n") if preamble_parts else ""
        final_text = f"{header}{preamble}{summary}\n\n---\n\n{full_report}"

        if self.settings.compliance_charts_in_report:
            try:
                final_text = (
                    f"{final_text.rstrip()}\n"
                    f"{format_compliance_markdown(full_report, language=report_lang)}"
                )
            except Exception:  # noqa: BLE001
                pass

        archive_path = ""
        archive_url = ""
        # Multi-framework runs package once in ``_merge_multi_reports``.
        run_id = state.get("evidence_run_id") or (store.run_id if store else "")
        in_multi = any(
            (sess.get("run_id") == run_id) for sess in self._multi_sessions.values()
        )
        if store is not None and self.settings.archive_enabled and not in_multi:
            try:
                store.write_root_report(final_text)
                packaged = await package_and_publish_archive(
                    store.root, self.settings
                )
                archive_path = str(packaged.get("zip_path") or "")
                archive_url = str(packaged.get("download_url") or "")
                final_text = f"{final_text.rstrip()}\n{packaged.get('chat_section') or ''}"
            except Exception as exc:  # noqa: BLE001
                final_text = (
                    f"{final_text.rstrip()}\n\n---\n\n"
                    f"(Archive packaging failed: {type(exc).__name__}: {exc})\n"
                )
        elif store is not None and not in_multi:
            store.write_root_report(final_text)

        final_text = f"{final_text.rstrip()}{followup_footer()}"

        return {
            "report": final_text,
            "evidence_run_id": state.get("evidence_run_id") or "",
            "evidence_run_dir": state.get("evidence_run_dir") or (
                str(store.root) if store else ""
            ),
            "archive_path": archive_path,
            "archive_url": archive_url,
            "pending_ids": [],
            "awaiting_hitl": False,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                AIMessage(content=final_text),
            ],
        }

    def _decorate_result(
        self,
        result: dict[str, Any],
        *,
        thread_id: str,
        store: EvidenceStore | None,
        intake: bool = False,
    ) -> dict[str, Any]:
        """Attach HITL/intake pause messaging when the graph returned ``__interrupt__``."""
        result = dict(result)
        result.setdefault("evidence_run_id", store.run_id if store else "")
        result.setdefault("evidence_run_dir", str(store.root) if store else "")
        result["thread_id"] = thread_id

        interrupts = result.get("__interrupt__") or []
        if not interrupts:
            result["awaiting_hitl"] = False
            return result

        first = interrupts[0]
        value = getattr(first, "value", first)
        prompt = interrupt_payload_to_prompt(value)
        is_intake = intake or (
            isinstance(value, dict) and str(value.get("type") or "") == "intake"
        )
        if is_intake:
            msg = format_intake_assistant_message(prompt, thread_id)
        else:
            msg = format_hitl_assistant_message(prompt, thread_id)
        result["report"] = msg
        result["awaiting_hitl"] = True
        result["awaiting_intake"] = is_intake
        result["messages"] = [AIMessage(content=msg)]
        return result

    async def arun_intake(
        self,
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
                self.settings.max_user_request_chars,
                "user_request",
            ),
            "report_language": report_lang.code,
            "evidence_run_id": store.run_id,
            "evidence_run_dir": str(store.root),
            "intake_complete": False,
            "intake": {},
        }
        config = {"configurable": {"thread_id": thread_id}}
        result = await self.intake_graph.ainvoke(initial, config)
        return self._decorate_result(result, thread_id=thread_id, store=store, intake=True)

    async def arun_one(
        self,
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
        store = self._evidence_by_run.get(rid)
        if store is None:
            store = EvidenceStore(self.settings.evidence_dir, run_id=rid)
            self._evidence_by_run[store.run_id] = store
        if evidence_host_id:
            store.host_segment = evidence_host_id
        meta: dict[str, Any] = {
            "user_request": truncate_text(
                user_text,
                self.settings.max_user_request_chars,
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
        store.write_run_meta(**meta)
        initial: AuditorState = {
            "messages": [HumanMessage(content=user_text)],
            "user_request": truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
            "report_language": report_lang.code,
            "retry_count": 0,
            "evidence_run_id": store.run_id,
            "evidence_run_dir": str(store.root),
            "hitl_skipped": [],
            "awaiting_hitl": False,
            "intake_complete": True,
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
        if framework_id:
            initial["framework_id"] = framework_id
        if evidence_host_id:
            initial["evidence_host_id"] = evidence_host_id
        config = {"configurable": {"thread_id": tid}}

        async def _invoke() -> dict[str, Any]:
            result = await self.graph.ainvoke(initial, config)
            return self._decorate_result(result, thread_id=tid, store=store)

        if ssh_target is not None:
            with bind_ssh_target(ssh_target):
                self.settings = get_settings()
                return await _invoke()
        return await _invoke()

    async def aresume(self, thread_id: str, user_text: str) -> dict[str, Any]:
        """Resume a graph paused on intake or ``human_gate``."""
        config = {"configurable": {"thread_id": thread_id}}
        is_intake = ":intake" in thread_id or thread_id.endswith("intake")
        graph = self.intake_graph if is_intake else self.graph
        result = await graph.ainvoke(Command(resume=user_text), config)
        snap = await graph.aget_state(config)
        values = snap.values or {}
        run_id = values.get("evidence_run_id") or ""
        store = self._evidence_by_run.get(run_id)
        if store is None and values.get("evidence_run_dir"):
            store = EvidenceStore(
                self.settings.evidence_dir,
                run_id=run_id or Path(str(values["evidence_run_dir"])).name,
            )
            self._evidence_by_run[store.run_id] = store
        decorated = self._decorate_result(
            result, thread_id=thread_id, store=store, intake=is_intake
        )
        if decorated.get("awaiting_hitl"):
            return decorated

        if is_intake and values.get("intake_complete"):
            # Continue into framework audits using intake answers.
            session = self._multi_sessions.pop(thread_id, None) or {}
            user_req = session.get("user_text") or values.get("user_request") or user_text
            base_thread = session.get("base_thread") or thread_id.replace(":intake", "")
            run_id = (
                values.get("evidence_run_id")
                or session.get("run_id")
                or run_id
            )
            intake = values.get("intake") or {}
            return await self._start_frameworks_after_intake(
                user_text=str(user_req),
                base_thread=base_thread,
                run_id=str(run_id),
                intake=intake if isinstance(intake, dict) else {},
            )

        # If this thread was part of a multi-framework run, continue the queue.
        return await self._continue_multi_after_resume(thread_id, decorated)

    async def _discover_inventory_hosts(
        self,
        *,
        intake: dict[str, Any],
        store: EvidenceStore,
    ) -> list[tuple[InventorySshTarget, HostFacts]]:
        """SSH-discover every inventory host (inventory-only when no CMDB)."""
        slug = str(intake.get("client_slug") or client_slug(str(intake.get("client_name") or "")))
        targets = list_client_ssh_targets(self.settings.inventory_dir, slug)
        if not targets and self.settings.ssh_host:
            targets = [
                InventorySshTarget(
                    host=self.settings.ssh_host,
                    port=str(self.settings.ssh_port or 22),
                    user=self.settings.ssh_user or "",
                    password=self.settings.ssh_password or "",
                    private_key_path=self.settings.ssh_private_key_path or "",
                )
            ]
        discovered: list[tuple[InventorySshTarget, HostFacts]] = []
        for target in targets:
            with bind_ssh_target(target):
                self.settings = get_settings()
                facts = await collect_host_facts_ssh()
            facts.ssh_host = target.host
            host_base = store.host_root(target.slug)
            write_host_facts_json(host_base / "host_facts.json", facts, [])
            md = format_host_facts_markdown(facts, None, language="en")
            (host_base / "host_facts.md").write_text(md, encoding="utf-8")
            discovered.append((target, facts))
        return discovered

    def _format_host_framework_plan(
        self,
        jobs: list[tuple[InventorySshTarget, HostFacts, Any]],
    ) -> str:
        lines = [
            "## Host → framework selection",
            "",
        ]
        if not jobs:
            lines.append(
                "_No hosts discovered — falling back to NLP framework routing._"
            )
            return "\n".join(lines)
        by_host: dict[str, list[str]] = {}
        labels: dict[str, str] = {}
        for target, facts, fw in jobs:
            key = target.slug
            labels[key] = (
                f"`{target.host}` "
                f"({facts.hostname or '—'}, {facts.os_id or 'os?'})"
            )
            by_host.setdefault(key, []).append(fw.id)
        for key, fws in by_host.items():
            lines.append(f"- {labels[key]} → {', '.join(f'`{x}`' for x in fws)}")
        lines.append("")
        return "\n".join(lines)

    async def _start_frameworks_after_intake(
        self,
        *,
        user_text: str,
        base_thread: str,
        run_id: str,
        intake: dict[str, Any],
    ) -> dict[str, Any]:
        audit_type = str(intake.get("audit_types") or "both")
        domains = domains_for_audit_type(audit_type)
        has_access = bool(intake.get("has_access"))

        store = self._evidence_by_run.get(run_id)
        if store is None:
            store = EvidenceStore(self.settings.evidence_dir, run_id=run_id)
            self._evidence_by_run[run_id] = store

        intake_state = {
            "intake_complete": True,
            "intake": intake,
            "client_name": str(intake.get("client_name") or ""),
            "has_cmdb": bool(intake.get("has_cmdb")),
            "has_access": has_access,
            "audit_types": audit_type,
        }

        # Jobs: (ssh_target, facts, framework)
        jobs: list[tuple[InventorySshTarget, HostFacts, Any]] = []
        if has_access:
            discovered = await self._discover_inventory_hosts(
                intake=intake, store=store
            )
            for target, facts in discovered:
                if facts.error:
                    # Still allow it_audit if domain includes IT
                    matched = []
                    if "it" in domains:
                        it_fw = get_framework("it_audit", self.settings.agents_dir)
                        if it_fw is not None:
                            matched = [it_fw]
                else:
                    matched = select_frameworks_for_host(
                        facts,
                        domains=domains,
                        agents_dir=self.settings.agents_dir,
                    )
                for fw in matched:
                    jobs.append((target, facts, fw))

        if not jobs:
            # Fallback: NLP routing without per-host discovery
            fw_ids = frameworks_for_audit_type(
                audit_type,  # type: ignore[arg-type]
                user_request=user_text,
                agents_dir=self.settings.agents_dir,
            )
            selected = []
            for fid in fw_ids:
                fw = get_framework(fid, self.settings.agents_dir)
                if fw is not None:
                    selected.append(fw)
            if not selected:
                selected = route_frameworks(user_text, self.settings.agents_dir)
            store.write_run_meta(
                frameworks=[fw.id for fw in selected],
                intake_complete=True,
                intake=intake,
                client_name=intake.get("client_name"),
                audit_types=audit_type,
                host_driven=False,
            )
            return await self._run_framework_jobs(
                user_text=user_text,
                base_thread=base_thread,
                run_id=run_id,
                intake_state=intake_state,
                jobs=[(None, None, fw) for fw in selected],
                plan_md="",
            )

        plan_md = self._format_host_framework_plan(jobs)
        store.write_run_meta(
            frameworks=[f"{t.slug}/{fw.id}" for t, _f, fw in jobs],
            intake_complete=True,
            intake=intake,
            client_name=intake.get("client_name"),
            audit_types=audit_type,
            host_driven=True,
            host_plan=plan_md,
        )
        return await self._run_framework_jobs(
            user_text=user_text,
            base_thread=base_thread,
            run_id=run_id,
            intake_state=intake_state,
            jobs=jobs,
            plan_md=plan_md,
        )

    async def _run_framework_jobs(
        self,
        *,
        user_text: str,
        base_thread: str,
        run_id: str,
        intake_state: dict[str, Any],
        jobs: list[tuple[InventorySshTarget | None, HostFacts | None, Any]],
        plan_md: str,
    ) -> dict[str, Any]:
        """Run ordered (host, framework) audits with HITL sequencing."""
        if not jobs:
            return {
                "report": "No frameworks selected.",
                "messages": [AIMessage(content="No frameworks selected.")],
                "awaiting_hitl": False,
            }

        def _job_key(target: InventorySshTarget | None, fw: Any) -> str:
            if target is None:
                return fw.id
            return f"{target.slug}/{fw.id}"

        def _thread_id(target: InventorySshTarget | None, fw: Any) -> str:
            if target is None:
                return f"{base_thread}:{fw.id}"
            return f"{base_thread}:{target.slug}:{fw.id}"

        if len(jobs) == 1:
            target, _facts, fw = jobs[0]
            result = await self.arun_one(
                user_text,
                framework_id=fw.id,
                run_id=run_id,
                thread_id=_thread_id(target, fw),
                intake_state=intake_state,
                evidence_host_id=target.slug if target else None,
                ssh_target=target,
            )
            if plan_md and not result.get("awaiting_hitl"):
                result["report"] = f"{plan_md}\n{result.get('report') or ''}"
            elif plan_md:
                result["report"] = f"{plan_md}\n{result.get('report') or ''}"
            return result

        # Always sequential for multi-host (SSH env binding is process-global).
        completed: list[tuple[str, str, str]] = []
        for index, (target, _facts, fw) in enumerate(jobs):
            key = _job_key(target, fw)
            fw_tid = _thread_id(target, fw)
            remaining = [_job_key(t, f) for t, _, f in jobs[index + 1 :]]
            self._multi_sessions[fw_tid] = {
                "base_thread": base_thread,
                "run_id": run_id,
                "user_text": user_text,
                "framework_id": fw.id,
                "framework_title": fw.title,
                "job_key": key,
                "evidence_host_id": target.slug if target else "",
                "ssh_target": target,
                "remaining_jobs": [
                    {
                        "framework_id": f.id,
                        "framework_title": f.title,
                        "evidence_host_id": t.slug if t else "",
                        "ssh_host": t.host if t else "",
                        "ssh_port": t.port if t else "",
                        "ssh_user": t.user if t else "",
                        "ssh_password": t.password if t else "",
                        "ssh_key": t.private_key_path if t else "",
                        "ssh_strict": t.strict_host_key if t else "",
                        "ssh_label": t.label if t else "",
                    }
                    for t, _, f in jobs[index + 1 :]
                ],
                "remaining": remaining,
                "completed": list(completed),
                "intake_state": intake_state,
                "plan_md": plan_md,
            }
            result = await self.arun_one(
                user_text,
                framework_id=fw.id,
                run_id=run_id,
                thread_id=fw_tid,
                intake_state=intake_state,
                evidence_host_id=target.slug if target else None,
                ssh_target=target,
            )
            if result.get("awaiting_hitl"):
                prefix = self._multi_progress_preamble(completed, key)
                preamble = f"{plan_md}\n{prefix}" if plan_md else prefix
                result["report"] = f"{preamble}{result.get('report') or ''}"
                return result
            self._multi_sessions.pop(fw_tid, None)
            title = fw.title if target is None else f"{target.host} — {fw.title}"
            completed.append((key, title, result.get("report") or ""))

        merged = await self._merge_multi_reports(
            completed,
            run_id=run_id,
            base_thread=base_thread,
        )
        if plan_md:
            merged["report"] = f"{plan_md}\n{merged.get('report') or ''}"
        return merged

    async def _continue_multi_after_resume(
        self,
        thread_id: str,
        finished: dict[str, Any],
    ) -> dict[str, Any]:
        session = self._multi_sessions.pop(thread_id, None)
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

        if not remaining_jobs and not remaining:
            merged = await self._merge_multi_reports(
                completed,
                run_id=str(run_id or ""),
                base_thread=base_thread,
            )
            if plan_md:
                merged["report"] = f"{plan_md}\n{merged.get('report') or ''}"
            return merged

        def _target_from_job(job: dict[str, Any]) -> InventorySshTarget | None:
            host = str(job.get("ssh_host") or "").strip()
            if not host:
                return None
            return InventorySshTarget(
                host=host,
                port=str(job.get("ssh_port") or "22"),
                user=str(job.get("ssh_user") or ""),
                password=str(job.get("ssh_password") or ""),
                private_key_path=str(job.get("ssh_key") or ""),
                strict_host_key=str(job.get("ssh_strict") or ""),
                label=str(job.get("ssh_label") or ""),
            )

        if remaining_jobs:
            nxt_job = remaining_jobs[0]
            next_id = str(nxt_job.get("framework_id") or "")
            next_host = str(nxt_job.get("evidence_host_id") or "")
            next_fw = get_framework(next_id, self.settings.agents_dir)
            next_title = next_fw.title if next_fw else next_id
            next_key = f"{next_host}/{next_id}" if next_host else next_id
            next_tid = (
                f"{base_thread}:{next_host}:{next_id}"
                if next_host
                else f"{base_thread}:{next_id}"
            )
            ssh_target = _target_from_job(nxt_job)
            self._multi_sessions[next_tid] = {
                "base_thread": base_thread,
                "run_id": run_id,
                "user_text": user_text,
                "framework_id": next_id,
                "framework_title": next_title,
                "job_key": next_key,
                "evidence_host_id": next_host,
                "ssh_target": ssh_target,
                "remaining_jobs": remaining_jobs[1:],
                "remaining": [str(j.get("framework_id") or "") for j in remaining_jobs[1:]],
                "completed": completed,
                "intake_state": intake_state,
                "plan_md": plan_md,
            }
            nxt = await self.arun_one(
                user_text,
                framework_id=next_id,
                run_id=run_id,
                thread_id=next_tid,
                intake_state=intake_state,
                evidence_host_id=next_host or None,
                ssh_target=ssh_target,
            )
            if nxt.get("awaiting_hitl"):
                prefix = self._multi_progress_preamble(completed, next_key)
                preamble = f"{plan_md}\n{prefix}" if plan_md else prefix
                nxt["report"] = f"{preamble}{nxt.get('report') or ''}"
                return nxt
            return await self._continue_multi_after_resume(next_tid, nxt)

        # Legacy remaining framework ids (no host)
        next_id = remaining[0]
        next_fw = get_framework(next_id, self.settings.agents_dir)
        title = next_fw.title if next_fw else next_id
        next_tid = f"{base_thread}:{next_id}"
        self._multi_sessions[next_tid] = {
            "base_thread": base_thread,
            "run_id": run_id,
            "user_text": user_text,
            "framework_id": next_id,
            "framework_title": title,
            "job_key": next_id,
            "remaining_jobs": [],
            "remaining": remaining[1:],
            "completed": completed,
            "intake_state": intake_state,
            "plan_md": plan_md,
        }
        nxt = await self.arun_one(
            user_text,
            framework_id=next_id,
            run_id=run_id,
            thread_id=next_tid,
            intake_state=intake_state,
        )
        if nxt.get("awaiting_hitl"):
            prefix = self._multi_progress_preamble(completed, next_id)
            nxt["report"] = f"{prefix}{nxt.get('report') or ''}"
            return nxt
        return await self._continue_multi_after_resume(next_tid, nxt)

    def _multi_progress_preamble(
        self,
        completed: list[tuple[str, str, str]],
        current_id: str,
    ) -> str:
        if not completed:
            return ""
        lines = [
            "# Multi-framework audit (in progress)",
            "",
            f"Completed before pause: {', '.join(f'`{c[0]}`' for c in completed)}",
            f"Now waiting on: `{current_id}`",
            "",
            "---",
            "",
        ]
        return "\n".join(lines)

    async def _merge_multi_reports(
        self,
        completed: list[tuple[str, str, str]],
        *,
        run_id: str,
        base_thread: str,
    ) -> dict[str, Any]:
        store = self._evidence_by_run.get(run_id)
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

        sections = [
            "# Multi-host / multi-framework audit",
            "",
            "Sections: " + ", ".join(f"`{c[0]}`" for c in completed),
            "",
        ]
        if store is not None:
            sections.extend([f"Evidence directory: `{store.root}`", ""])
        for fw_id, title, report in completed:
            sections.append(f"## `{fw_id}` — {title}")
            sections.append("")
            body = (disk_reports.get(fw_id) or report or "(empty report)").strip()
            if "## Audit archive" in body:
                body = body.split("## Audit archive", 1)[0].rstrip()
            sections.append(body)
            sections.append("")
            sections.append("---")
            sections.append("")
        # Include any extra on-disk framework reports not listed in completed.
        known = {c[0] for c in completed}
        for fw_id, body in disk_reports.items():
            if fw_id in known:
                continue
            sections.append(f"## `{fw_id}`")
            sections.append("")
            if "## Audit archive" in body:
                body = body.split("## Audit archive", 1)[0].rstrip()
            sections.append(body.strip())
            sections.append("")
            sections.append("---")
            sections.append("")
        combined = "\n".join(sections).strip() + "\n"
        archive_path = ""
        archive_url = ""
        if store is not None:
            store.write_root_report(combined)
            if self.settings.archive_enabled:
                try:
                    packaged = await package_and_publish_archive(
                        store.root, self.settings
                    )
                    archive_path = str(packaged.get("zip_path") or "")
                    archive_url = str(packaged.get("download_url") or "")
                    combined = (
                        f"{combined.rstrip()}\n{packaged.get('chat_section') or ''}"
                    )
                except Exception as exc:  # noqa: BLE001
                    combined = (
                        f"{combined.rstrip()}\n\n---\n\n"
                        f"(Archive packaging failed: {type(exc).__name__}: {exc})\n"
                    )
        return {
            "report": combined,
            "messages": [AIMessage(content=combined)],
            "framework_id": ",".join(c[0] for c in completed),
            "evidence_run_id": run_id,
            "evidence_run_dir": str(store.root) if store else "",
            "archive_path": archive_path,
            "archive_url": archive_url,
            "thread_id": base_thread,
            "awaiting_hitl": False,
            "findings": {},
        }

    async def arun_revise_req(
        self,
        user_text: str,
        *,
        messages: list | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Gather more evidence (and optionally refill cells) into the prior run."""
        del thread_id
        return await run_revise_req(self, user_text, messages=messages)

    async def arun_refill_finding(
        self,
        user_text: str,
        *,
        messages: list | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Rewrite observation/recommendation from stored evidence only."""
        del thread_id
        return await run_refill_finding(self, user_text, messages=messages)

    async def arun_update_report(
        self,
        user_text: str,
        *,
        messages: list | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Rebuild report.md / ZIP from on-disk findings after follow-up checks."""
        del thread_id
        return await run_update_report(self, user_text, messages=messages)

    async def arun_adhoc(
        self,
        user_text: str,
        *,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Run operator-requested audit commands (no checklist report).

        Args:
            user_text: Operator message asking to run SSH/SQL/playbook commands.
            thread_id: Unused today (reserved for future HITL on ad-hoc).

        Returns:
            Result dict with ``report`` Markdown and ``adhoc=True``.
        """
        del thread_id
        if not self.settings.adhoc_commands_enabled:
            return await self.arun(user_text)
        return await run_adhoc_commands(self, user_text)

    async def arun(
        self,
        user_text: str,
        *,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Run audit(s) for the request.

        When intake is enabled, asks client/CMDB/access/audit-type first, then
        runs one or more framework graphs. Multiple frameworks run as separate
        graphs (sequential when HITL is on).
        """
        run_id = new_run_id()
        base_thread = thread_id or f"audit-{uuid.uuid4().hex[:12]}"
        shared = EvidenceStore(self.settings.evidence_dir, run_id=run_id)
        self._evidence_by_run[run_id] = shared
        shared.write_run_meta(
            user_request=truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
            thread_id=base_thread,
        )

        if self.settings.intake_enabled:
            intake_tid = f"{base_thread}:intake"
            self._multi_sessions[intake_tid] = {
                "base_thread": base_thread,
                "run_id": run_id,
                "user_text": user_text,
            }
            intake_result = await self.arun_intake(
                user_text,
                run_id=run_id,
                thread_id=intake_tid,
                store=shared,
            )
            if intake_result.get("awaiting_hitl"):
                return intake_result
            # Intake finished in one shot (should be rare without interrupts)
            snap = await self.intake_graph.aget_state(
                {"configurable": {"thread_id": intake_tid}}
            )
            intake = (snap.values or {}).get("intake") or {}
            self._multi_sessions.pop(intake_tid, None)
            return await self._start_frameworks_after_intake(
                user_text=user_text,
                base_thread=base_thread,
                run_id=run_id,
                intake=intake if isinstance(intake, dict) else {},
            )

        try:
            selected = route_frameworks(user_text, self.settings.agents_dir)
        except FileNotFoundError as exc:
            return {
                "report": str(exc),
                "messages": [AIMessage(content=str(exc))],
                "error": str(exc),
            }

        shared.write_run_meta(frameworks=[fw.id for fw in selected])

        if len(selected) == 1:
            return await self.arun_one(
                user_text,
                framework_id=selected[0].id,
                run_id=run_id,
                thread_id=f"{base_thread}:{selected[0].id}",
            )

        # HITL-friendly sequential graphs (parallel would tangle chat interrupts).
        if self.settings.hitl_enabled:
            completed: list[tuple[str, str, str]] = []
            for index, fw in enumerate(selected):
                fw_tid = f"{base_thread}:{fw.id}"
                remaining = [f.id for f in selected[index + 1 :]]
                self._multi_sessions[fw_tid] = {
                    "base_thread": base_thread,
                    "run_id": run_id,
                    "user_text": user_text,
                    "framework_id": fw.id,
                    "framework_title": fw.title,
                    "remaining": remaining,
                    "completed": list(completed),
                }
                result = await self.arun_one(
                    user_text,
                    framework_id=fw.id,
                    run_id=run_id,
                    thread_id=fw_tid,
                )
                if result.get("awaiting_hitl"):
                    prefix = self._multi_progress_preamble(completed, fw.id)
                    result["report"] = f"{prefix}{result.get('report') or ''}"
                    return result
                self._multi_sessions.pop(fw_tid, None)
                completed.append((fw.id, fw.title, result.get("report") or ""))
            return await self._merge_multi_reports(
                completed,
                run_id=run_id,
                base_thread=base_thread,
            )

        results = await asyncio.gather(
            *[
                self.arun_one(
                    user_text,
                    framework_id=fw.id,
                    run_id=run_id,
                    thread_id=f"{base_thread}:{fw.id}",
                )
                for fw in selected
            ]
        )
        completed = [
            (fw.id, fw.title, result.get("report") or "")
            for fw, result in zip(selected, results, strict=True)
        ]
        return await self._merge_multi_reports(
            completed,
            run_id=run_id,
            base_thread=base_thread,
        )


_graph: AuditorGraph | None = None


def get_auditor_graph() -> AuditorGraph:
    global _graph
    if _graph is None:
        _graph = AuditorGraph()
    return _graph

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

from psql_auditor.checklist import Requirement
from psql_auditor.compliance import format_compliance_markdown
from psql_auditor.config import Settings, get_settings
from psql_auditor.context import (
    compact_findings_for_summary,
    count_tool_rounds,
    truncate_text,
)
from psql_auditor.evidence_store import EvidenceStore, new_run_id
from psql_auditor.frameworks import (
    frameworks_catalog_text,
    get_framework,
    load_framework_checklist,
    route_framework,
    route_frameworks,
)
from psql_auditor.hitl import (
    build_hitl_prompt,
    format_hitl_assistant_message,
    interrupt_payload_to_prompt,
    parse_hitl_decision,
)
from psql_auditor.memory.playbook_store import PlaybookMemory
from psql_auditor.report_archive import package_and_publish_archive
from psql_auditor.llm import build_chat_model
from psql_auditor.prompts import (
    EVIDENCE_FORCE_PROMPT,
    EVIDENCE_PROMPT,
    EVIDENCE_SYSTEM_PROMPT,
    FILL_CELL_PROMPT,
    FILL_SYSTEM_PROMPT,
    FINALIZE_PROMPT,
)
from psql_auditor.state import AuditorState, Finding, render_report
from psql_auditor.tools.mcp_client import get_mcp_tools, reconnect_mcp_session
from psql_auditor.tools.ssh import get_ssh_tools

_RECOVERABLE_MARKERS = (
    "mcp error",
    "mcp reconnect failed",
    "ssh error",
    "session",
    "connection refused",
    "connection reset",
    "broken pipe",
    "eof",
    "not connected",
    "timeout",
)


def _all_tools() -> list:
    """SSH + MCP tools available to every framework worker."""
    return [*get_ssh_tools(), *get_mcp_tools()]


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
        self.tools = _all_tools()
        self.tools_by_name = {t.name: t for t in self.tools}
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
        self.fill_model = build_chat_model(self.settings)
        self.graph = self._build()

    def _build(self):
        graph = StateGraph(AuditorState)
        graph.add_node("route_framework", self.route_framework_node)
        graph.add_node("load_framework", self.load_framework)
        graph.add_node("assess_parallel", self.assess_parallel)
        graph.add_node("reconnect_session", self.reconnect_session)
        graph.add_node("human_gate", self.human_gate)
        graph.add_node("finalize", self.finalize)

        graph.add_edge(START, "route_framework")
        graph.add_edge("route_framework", "load_framework")
        graph.add_edge("load_framework", "assess_parallel")
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
            "framework_id": fw.id,
            "framework_title": fw.title,
            "retry_count": 0,
            "error": None,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                SystemMessage(
                    content=(
                        f"Selected framework `{fw.id}` ({fw.title}) from agents/.\n"
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
        store = self._store_from_state(state)
        limit = max(1, self.settings.max_parallel_assessments)
        sem = asyncio.Semaphore(limit)

        async def _worker(req_id: str) -> Finding:
            async with sem:
                try:
                    return await self._fill_requirement_cells(
                        req_id=req_id,
                        requirement=requirements[req_id],
                        user_request=user_request,
                        framework_id=framework_id,
                        store=store,
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

        # retry single
        return {
            "pending_ids": [req_id],
            "awaiting_hitl": False,
            "messages": [
                AIMessage(
                    content=f"Operator requested retry for `{req_id}`.",
                    name="auditor",
                )
            ],
        }

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
            req_id, requirement, user_request, framework_id, store=store
        )
        evidence = truncate_text(
            evidence,
            self.settings.max_tool_output_chars,
            "evidence",
        )
        fill_messages = [
            SystemMessage(content=FILL_SYSTEM_PROMPT),
            HumanMessage(
                content=FILL_CELL_PROMPT.format(
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
    ) -> str:
        playbook_block = ""
        if self.playbooks is not None and self.settings.memory_enabled:
            playbook_block = self.playbooks.format_prompt_block(framework_id, req_id)
        messages: list = [
            SystemMessage(
                content=(
                    f"{EVIDENCE_SYSTEM_PROMPT}\n\n"
                    f"Active framework: `{framework_id}`. "
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

        for _ in range(max_rounds + 1):
            rounds = count_tool_rounds(messages)
            if rounds >= max_rounds:
                messages.append(HumanMessage(content=EVIDENCE_FORCE_PROMPT))
                response = await self.fill_model.ainvoke(messages)
                chunks.append(str(response.content or ""))
                break

            response = await self.evidence_model.ainvoke(messages)
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
    ) -> list[ToolMessage]:
        async def _one(tc: dict[str, Any]) -> ToolMessage:
            name = tc.get("name") or ""
            args = tc.get("args") or {}
            call_id = tc.get("id") or name
            tool = self.tools_by_name.get(name)
            error: str | None = None
            full_result = ""
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
        if _is_recoverable_finding(
            Finding(
                requirement_id=req_id,
                status="error",
                evidence=observation,
            )
        ) and status == "pass":
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
        full_report = render_report(title, findings, requirements)
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
                            "security audit reports across OS/DB frameworks."
                        )
                    ),
                    HumanMessage(content=FINALIZE_PROMPT.format(report=digest)),
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
            store.write_report(fw or "framework", f"{summary}\n\n---\n\n{full_report}")
            evidence_note = f" | evidence: `{store.root}`"
        header = (
            f"Framework: `{fw}` | session reconnects: {retries}{evidence_note}\n\n"
        )
        final_text = f"{header}{summary}\n\n---\n\n{full_report}"

        if self.settings.compliance_charts_in_report:
            try:
                final_text = (
                    f"{final_text.rstrip()}\n"
                    f"{format_compliance_markdown(full_report)}"
                )
            except Exception:  # noqa: BLE001
                pass

        archive_path = ""
        archive_url = ""
        if store is not None and self.settings.archive_enabled:
            try:
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
    ) -> dict[str, Any]:
        """Attach HITL pause messaging when the graph returned ``__interrupt__``."""
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
        msg = format_hitl_assistant_message(prompt, thread_id)
        result["report"] = msg
        result["awaiting_hitl"] = True
        result["messages"] = [AIMessage(content=msg)]
        return result

    async def arun_one(
        self,
        user_text: str,
        *,
        framework_id: str | None = None,
        run_id: str | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a single-framework audit graph (optionally pinned)."""
        rid = run_id or new_run_id()
        tid = thread_id or f"audit-{uuid.uuid4().hex[:12]}"
        store = self._evidence_by_run.get(rid)
        if store is None:
            store = EvidenceStore(self.settings.evidence_dir, run_id=rid)
            self._evidence_by_run[store.run_id] = store
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
        store.write_run_meta(**meta)
        initial: AuditorState = {
            "messages": [HumanMessage(content=user_text)],
            "user_request": truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
            "retry_count": 0,
            "evidence_run_id": store.run_id,
            "evidence_run_dir": str(store.root),
            "hitl_skipped": [],
            "awaiting_hitl": False,
        }
        if framework_id:
            initial["framework_id"] = framework_id
        config = {"configurable": {"thread_id": tid}}
        result = await self.graph.ainvoke(initial, config)
        return self._decorate_result(result, thread_id=tid, store=store)

    async def aresume(self, thread_id: str, user_text: str) -> dict[str, Any]:
        """Resume a graph paused on ``human_gate`` with the operator's reply."""
        config = {"configurable": {"thread_id": thread_id}}
        result = await self.graph.ainvoke(Command(resume=user_text), config)
        snap = await self.graph.aget_state(config)
        values = snap.values or {}
        run_id = values.get("evidence_run_id") or ""
        store = self._evidence_by_run.get(run_id)
        if store is None and values.get("evidence_run_dir"):
            store = EvidenceStore(
                self.settings.evidence_dir,
                run_id=run_id or Path(str(values["evidence_run_dir"])).name,
            )
            self._evidence_by_run[store.run_id] = store
        decorated = self._decorate_result(result, thread_id=thread_id, store=store)
        if decorated.get("awaiting_hitl"):
            return decorated
        # If this thread was part of a multi-framework run, continue the queue.
        return await self._continue_multi_after_resume(thread_id, decorated)

    async def _continue_multi_after_resume(
        self,
        thread_id: str,
        finished: dict[str, Any],
    ) -> dict[str, Any]:
        session = self._multi_sessions.pop(thread_id, None)
        if not session:
            return finished

        completed: list[tuple[str, str, str]] = list(session.get("completed") or [])
        fw_id = session.get("framework_id") or finished.get("framework_id") or ""
        fw_title = session.get("framework_title") or fw_id
        completed.append((fw_id, fw_title, finished.get("report") or ""))

        remaining: list[str] = list(session.get("remaining") or [])
        user_text = session.get("user_text") or ""
        run_id = session.get("run_id") or finished.get("evidence_run_id")
        base_thread = session.get("base_thread") or thread_id.split(":")[0]

        if not remaining:
            return await self._merge_multi_reports(
                completed,
                run_id=str(run_id or ""),
                base_thread=base_thread,
            )

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
            "remaining": remaining[1:],
            "completed": completed,
        }
        nxt = await self.arun_one(
            user_text,
            framework_id=next_id,
            run_id=run_id,
            thread_id=next_tid,
        )
        if nxt.get("awaiting_hitl"):
            prefix = self._multi_progress_preamble(completed, next_id)
            nxt["report"] = f"{prefix}{nxt.get('report') or ''}"
            return nxt
        # Finished next without pause — keep draining.
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
        sections = [
            "# Multi-framework audit",
            "",
            "Frameworks: " + ", ".join(f"`{c[0]}`" for c in completed),
            "",
        ]
        if store is not None:
            sections.extend([f"Evidence directory: `{store.root}`", ""])
        for fw_id, title, report in completed:
            sections.append(f"## Framework: `{fw_id}` — {title}")
            sections.append("")
            # Drop nested per-framework archive blocks; one zip at the end.
            body = (report or "(empty report)").strip()
            if "## Audit archive" in body:
                body = body.split("## Audit archive", 1)[0].rstrip()
            sections.append(body)
            sections.append("")
            sections.append("---")
            sections.append("")
        combined = "\n".join(sections).strip() + "\n"
        archive_path = ""
        archive_url = ""
        if store is not None:
            (store.root / "report.md").write_text(combined, encoding="utf-8")
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

    async def arun(
        self,
        user_text: str,
        *,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Run audit(s) for the request.

        Multiple frameworks run as **separate graphs**. When HITL is enabled they
        run **sequentially** so skip/retry prompts stay clear in Open WebUI.
        Without HITL (or a single framework) parallel gather is used when safe.
        """
        try:
            selected = route_frameworks(user_text, self.settings.agents_dir)
        except FileNotFoundError as exc:
            return {
                "report": str(exc),
                "messages": [AIMessage(content=str(exc))],
                "error": str(exc),
            }

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
            frameworks=[fw.id for fw in selected],
            thread_id=base_thread,
        )

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

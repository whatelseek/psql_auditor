"""LangGraph workflow: load checklist → assess each item → finalize report.

Control flow (high level)::

    START
      → load_checklist   # parse MD, seed pending_ids
      → select_next      # pop next REQ-*; **reset message window**
         ├─(has item)→ assess_item ⇄ tools   # isolated ReAct loop per item
         └─(none)────→ finalize → END        # compact digest → summary + full report

Quality + context policy:

* One requirement per LLM window (no cross-item transcript accumulation).
* Tool outputs truncated; tool rounds capped; then forced JSON decision.
* Finalize LLM sees a compact findings digest; full report stays in the response.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langgraph.prebuilt import ToolNode

from psql_auditor.checklist import Requirement, load_checklist
from psql_auditor.config import Settings, get_settings
from psql_auditor.context import (
    compact_findings_for_summary,
    count_tool_rounds,
    truncate_text,
    truncate_tool_messages,
)
from psql_auditor.llm import build_chat_model
from psql_auditor.prompts import (
    ASSESS_PROMPT,
    FINALIZE_PROMPT,
    FORCE_DECIDE_PROMPT,
    SYSTEM_PROMPT,
)
from psql_auditor.state import AuditorState, Finding, render_report
from psql_auditor.tools.mcp_client import get_mcp_tools
from psql_auditor.tools.ssh import get_ssh_tools


def _all_tools() -> list:
    """Collect every LangChain tool bound into the assess-loop model.

    Database access is MCP-only (antonorlov/mcp-postgres-server via
    ``mcp_query`` and related helpers). Direct ``run_sql`` is not bound.

    Returns:
        Flat list of SSH + MCP tool callables for ``bind_tools`` / ``ToolNode``.
    """
    return [*get_ssh_tools(), *get_mcp_tools()]


def _extract_json(text: str) -> dict[str, Any] | None:
    """Best-effort parse of a JSON object from model output."""
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
    """Clamp a free-form status string to the allowed FindingStatus set."""
    allowed = {"pass", "fail", "partial", "error", "skipped"}
    status = (value or "error").strip().lower()
    return status if status in allowed else "error"


class AuditorGraph:
    """Compile and run the PostgreSQL checklist audit StateGraph.

    Holds:

    * ``model`` — chat model with tools bound (used during assessment)
    * ``plain_model`` — same LiteLLM model without tools (force-decide / finalize)
    * ``tool_node`` — executes tool calls requested by the model
    * ``graph`` — compiled LangGraph runnable (``ainvoke`` / ``astream_events``)
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize models, tools, and compile the graph."""
        self.settings = settings or get_settings()
        self.tools = _all_tools()
        self.model = build_chat_model(self.settings).bind_tools(self.tools)
        self.plain_model = build_chat_model(self.settings)
        self.tool_node = ToolNode(self.tools)
        self.graph = self._build()

    def _build(self):
        """Wire nodes and edges into a compiled LangGraph."""
        graph = StateGraph(AuditorState)
        graph.add_node("load_checklist", self.load_checklist)
        graph.add_node("select_next", self.select_next)
        graph.add_node("assess_item", self.assess_item)
        graph.add_node("tools", self.run_tools)
        graph.add_node("finalize", self.finalize)

        graph.add_edge(START, "load_checklist")
        graph.add_edge("load_checklist", "select_next")
        graph.add_conditional_edges(
            "select_next",
            self.route_after_select,
            {"assess_item": "assess_item", "finalize": "finalize"},
        )
        graph.add_conditional_edges(
            "assess_item",
            self.route_after_assess,
            {"tools": "tools", "select_next": "select_next"},
        )
        graph.add_edge("tools", "assess_item")
        graph.add_edge("finalize", END)
        return graph.compile()

    async def load_checklist(self, state: AuditorState) -> dict[str, Any]:
        """Node: parse the Markdown checklist and initialize run state."""
        checklist = load_checklist(self.settings.checklist_path)
        req_map: dict[str, Requirement] = checklist.by_id()
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
        return {
            "checklist_title": checklist.title,
            "requirements": req_map,
            "pending_ids": checklist.ids(),
            "findings": {},
            "current_id": None,
            "report": "",
            "user_request": user_request,
            # Start empty; select_next installs a fresh window per item.
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                SystemMessage(content=SYSTEM_PROMPT),
            ],
        }

    async def select_next(self, state: AuditorState) -> dict[str, Any]:
        """Node: dequeue the next requirement and reset the message window.

        Clearing messages between items is the main context-safety mechanism:
        prior tool dumps and assessments do not accumulate across the checklist.
        Findings remain in ``findings`` for the final report.
        """
        pending = list(state.get("pending_ids") or [])
        if not pending:
            return {
                "current_id": None,
                "messages": [
                    RemoveMessage(id=REMOVE_ALL_MESSAGES),
                    SystemMessage(content=SYSTEM_PROMPT),
                ],
            }
        current = pending.pop(0)
        done = len(state.get("findings") or {})
        total = done + 1 + len(pending)
        progress = (
            f"{SYSTEM_PROMPT}\n\n"
            f"[Audit progress: starting {current} ({done + 1}/{total} assessed after this item). "
            f"Prior findings are stored separately — focus only on this requirement.]"
        )
        return {
            "current_id": current,
            "pending_ids": pending,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                SystemMessage(content=progress),
            ],
        }

    def route_after_select(
        self, state: AuditorState
    ) -> Literal["assess_item", "finalize"]:
        """Conditional edge: assess when a requirement is selected, else finish."""
        return "assess_item" if state.get("current_id") else "finalize"

    async def run_tools(self, state: AuditorState) -> dict[str, Any]:
        """Node: execute tool calls, then truncate outputs for context safety."""
        result = await self.tool_node.ainvoke(state)
        messages = result.get("messages") or []
        truncated = truncate_tool_messages(
            messages if isinstance(messages, list) else [messages],
            self.settings.max_tool_output_chars,
        )
        return {"messages": truncated}

    async def assess_item(self, state: AuditorState) -> dict[str, Any]:
        """Node: assess the current checklist requirement with tools + LLM.

        Uses only the current per-item message window. After ``max_tool_rounds``
        ReAct iterations, switches to the tool-free model with
        ``FORCE_DECIDE_PROMPT`` so the run cannot stall or balloon context.
        """
        req_id = state.get("current_id")
        requirements = state.get("requirements") or {}
        if not req_id or req_id not in requirements:
            return {
                "current_id": None,
                "findings": {
                    req_id
                    or "UNKNOWN": Finding(
                        requirement_id=req_id or "UNKNOWN",
                        status="error",
                        evidence="Requirement missing from checklist state",
                    )
                },
            }

        messages = list(state.get("messages") or [])
        last = messages[-1] if messages else None

        # Idempotent path: JSON answer already present without tool_calls.
        if (
            isinstance(last, AIMessage)
            and not getattr(last, "tool_calls", None)
            and not str(last.content).startswith("Recorded ")
            and self._recent_prompt_for(messages, req_id)
        ):
            finding = self._finding_from_ai(req_id, requirements[req_id], last)
            return self._recorded_update(req_id, finding)

        continuing = isinstance(last, ToolMessage) or (
            isinstance(last, AIMessage) and bool(getattr(last, "tool_calls", None))
        )

        invoke_messages = messages
        new_messages: list = []
        if not continuing:
            prompt = ASSESS_PROMPT.format(
                user_request=state.get("user_request") or "(none)",
                requirement_block=requirements[req_id].to_prompt_block(),
            )
            human = HumanMessage(content=prompt)
            invoke_messages = messages + [human]
            new_messages.append(human)

        rounds = count_tool_rounds(invoke_messages)
        force_decide = rounds >= self.settings.max_tool_rounds_per_item

        if force_decide:
            force = HumanMessage(content=FORCE_DECIDE_PROMPT)
            invoke_messages = invoke_messages + [force]
            new_messages.append(force)
            response = await self.plain_model.ainvoke(invoke_messages)
            new_messages.append(response)
            finding = self._finding_from_ai(req_id, requirements[req_id], response)
            return self._recorded_update(req_id, finding, extra_messages=new_messages)

        response = await self.model.ainvoke(invoke_messages)
        new_messages.append(response)

        if getattr(response, "tool_calls", None):
            return {"messages": new_messages}

        finding = self._finding_from_ai(req_id, requirements[req_id], response)
        return self._recorded_update(req_id, finding, extra_messages=new_messages)

    def _recorded_update(
        self,
        req_id: str,
        finding: Finding,
        extra_messages: list | None = None,
    ) -> dict[str, Any]:
        """Build state update after a finding is ready.

        Appends a short marker only (window will be wiped on the next
        ``select_next``). Truncates evidence for storage size / report safety.
        """
        finding.evidence = truncate_text(
            finding.evidence or "",
            self.settings.max_finding_evidence_chars,
            "evidence",
        )
        finding.remediation = truncate_text(
            finding.remediation or "",
            min(self.settings.max_finding_evidence_chars, 1200),
            "remediation",
        )
        msgs = list(extra_messages or [])
        msgs.append(
            AIMessage(content=f"Recorded {req_id}: {finding.status}", name="auditor")
        )
        return {"messages": msgs, "findings": {req_id: finding}}

    def _recent_prompt_for(self, messages: list, req_id: str) -> bool:
        """Return True if a recent HumanMessage mentions ``req_id``."""
        for msg in reversed(messages[-20:]):
            if isinstance(msg, HumanMessage) and req_id in str(msg.content):
                return True
            if isinstance(msg, AIMessage) and str(msg.content).startswith("Recorded "):
                break
        return False

    def _finding_from_ai(
        self, req_id: str, req: Requirement, ai: AIMessage
    ) -> Finding:
        """Convert an assistant JSON (or prose) reply into a Finding."""
        data = _extract_json(str(ai.content or "")) or {}
        return Finding(
            requirement_id=req_id,
            title=req.title,
            status=_normalize_status(data.get("status")),  # type: ignore[arg-type]
            severity=req.severity,
            category=req.category,
            evidence=str(data.get("evidence") or ai.content or ""),
            remediation=str(data.get("remediation") or ""),
            notes=str(data.get("notes") or ""),
        )

    def route_after_assess(
        self, state: AuditorState
    ) -> Literal["tools", "select_next"]:
        """Route to tools only when the latest AI message requested tool calls."""
        last = (state.get("messages") or [])[-1] if state.get("messages") else None
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            return "tools"
        return "select_next"

    async def finalize(self, state: AuditorState) -> dict[str, Any]:
        """Node: executive summary from a compact digest + full Markdown report.

        The LLM only sees the compact digest (safe context). The operator still
        receives the full structured report in the API response.
        """
        findings = state.get("findings") or {}
        requirements = state.get("requirements") or {}
        full_report = render_report(
            state.get("checklist_title") or "PostgreSQL Checklist",
            findings,
            requirements,
        )
        digest = compact_findings_for_summary(
            findings,
            evidence_chars=self.settings.max_finalize_evidence_chars,
        )
        summary_prompt = FINALIZE_PROMPT.format(report=digest)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=summary_prompt),
        ]
        try:
            response = await self.plain_model.ainvoke(messages)
            summary = str(response.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            summary = f"(Summary generation failed: {exc})"

        final_text = f"{summary}\n\n---\n\n{full_report}"
        return {
            "report": final_text,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                AIMessage(content=final_text),
            ],
        }

    async def arun(self, user_text: str) -> dict[str, Any]:
        """Convenience wrapper: run a full audit for a single user prompt."""
        initial: AuditorState = {
            "messages": [HumanMessage(content=user_text)],
            "user_request": truncate_text(
                user_text,
                self.settings.max_user_request_chars,
                "user_request",
            ),
        }
        return await self.graph.ainvoke(initial)


_graph: AuditorGraph | None = None


def get_auditor_graph() -> AuditorGraph:
    """Return a lazily constructed process-wide AuditorGraph."""
    global _graph
    if _graph is None:
        _graph = AuditorGraph()
    return _graph

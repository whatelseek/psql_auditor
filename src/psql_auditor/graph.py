"""LangGraph workflow: load checklist → assess each item → finalize report."""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from psql_auditor.checklist import Requirement, load_checklist
from psql_auditor.config import Settings, get_settings
from psql_auditor.llm import build_chat_model
from psql_auditor.prompts import ASSESS_PROMPT, FINALIZE_PROMPT, SYSTEM_PROMPT
from psql_auditor.state import AuditorState, Finding, render_report
from psql_auditor.tools.mcp_client import get_mcp_tools
from psql_auditor.tools.postgres import get_postgres_tools
from psql_auditor.tools.ssh import get_ssh_tools


def _all_tools() -> list:
    return [*get_ssh_tools(), *get_postgres_tools(), *get_mcp_tools()]


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


class AuditorGraph:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.tools = _all_tools()
        self.model = build_chat_model(self.settings).bind_tools(self.tools)
        self.plain_model = build_chat_model(self.settings)
        self.tool_node = ToolNode(self.tools)
        self.graph = self._build()

    def _build(self):
        graph = StateGraph(AuditorState)
        graph.add_node("load_checklist", self.load_checklist)
        graph.add_node("select_next", self.select_next)
        graph.add_node("assess_item", self.assess_item)
        graph.add_node("tools", self.tool_node)
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
        checklist = load_checklist(self.settings.checklist_path)
        req_map: dict[str, Requirement] = checklist.by_id()
        user_request = state.get("user_request") or ""
        if not user_request:
            for msg in reversed(state.get("messages") or []):
                if isinstance(msg, HumanMessage):
                    user_request = str(msg.content)
                    break
        return {
            "checklist_title": checklist.title,
            "requirements": req_map,
            "pending_ids": checklist.ids(),
            "findings": {},
            "current_id": None,
            "report": "",
            "user_request": user_request,
            "messages": [SystemMessage(content=SYSTEM_PROMPT)],
        }

    async def select_next(self, state: AuditorState) -> dict[str, Any]:
        pending = list(state.get("pending_ids") or [])
        if not pending:
            return {"current_id": None}
        current = pending.pop(0)
        return {"current_id": current, "pending_ids": pending}

    def route_after_select(
        self, state: AuditorState
    ) -> Literal["assess_item", "finalize"]:
        return "assess_item" if state.get("current_id") else "finalize"

    async def assess_item(self, state: AuditorState) -> dict[str, Any]:
        req_id = state.get("current_id")
        requirements = state.get("requirements") or {}
        if not req_id or req_id not in requirements:
            # Avoid infinite loops if state is inconsistent.
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

        # After tools: model already replied with final JSON (no tool calls).
        if (
            isinstance(last, AIMessage)
            and not getattr(last, "tool_calls", None)
            and not str(last.content).startswith("Recorded ")
            and self._recent_prompt_for(messages, req_id)
        ):
            finding = self._finding_from_ai(req_id, requirements[req_id], last)
            return {
                "findings": {req_id: finding},
                "messages": [
                    AIMessage(
                        content=f"Recorded {req_id}: {finding.status}",
                        name="auditor",
                    )
                ],
            }

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

        response = await self.model.ainvoke(invoke_messages)
        new_messages.append(response)

        if getattr(response, "tool_calls", None):
            return {"messages": new_messages}

        finding = self._finding_from_ai(req_id, requirements[req_id], response)
        new_messages.append(
            AIMessage(content=f"Recorded {req_id}: {finding.status}", name="auditor")
        )
        return {"messages": new_messages, "findings": {req_id: finding}}

    def _recent_prompt_for(self, messages: list, req_id: str) -> bool:
        for msg in reversed(messages[-20:]):
            if isinstance(msg, HumanMessage) and req_id in str(msg.content):
                return True
            if isinstance(msg, AIMessage) and str(msg.content).startswith("Recorded "):
                break
        return False

    def _finding_from_ai(
        self, req_id: str, req: Requirement, ai: AIMessage
    ) -> Finding:
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
        last = (state.get("messages") or [])[-1] if state.get("messages") else None
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            return "tools"
        return "select_next"

    async def finalize(self, state: AuditorState) -> dict[str, Any]:
        findings = state.get("findings") or {}
        requirements = state.get("requirements") or {}
        report = render_report(
            state.get("checklist_title") or "PostgreSQL Checklist",
            findings,
            requirements,
        )
        summary_prompt = FINALIZE_PROMPT.format(report=report)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=summary_prompt),
        ]
        try:
            response = await self.plain_model.ainvoke(messages)
            summary = str(response.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            summary = f"(Summary generation failed: {exc})"

        final_text = f"{summary}\n\n---\n\n{report}"
        return {
            "report": final_text,
            "messages": [AIMessage(content=final_text)],
        }

    async def arun(self, user_text: str) -> dict[str, Any]:
        initial: AuditorState = {
            "messages": [HumanMessage(content=user_text)],
            "user_request": user_text,
        }
        return await self.graph.ainvoke(initial)


_graph: AuditorGraph | None = None


def get_auditor_graph() -> AuditorGraph:
    global _graph
    if _graph is None:
        _graph = AuditorGraph()
    return _graph

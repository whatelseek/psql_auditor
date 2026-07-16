"""LangGraph workflow: load checklist → assess each item → finalize report.

Control flow (high level)::

    START
      → load_checklist   # parse MD, seed pending_ids, system prompt
      → select_next      # pop next REQ-* or clear current_id
         ├─(has item)→ assess_item ⇄ tools   # ReAct-style tool loop per item
         └─(none)────→ finalize → END        # summary + Markdown report

``assess_item`` asks the LLM (via LiteLLM) to evaluate exactly one requirement.
If the model emits tool calls, control moves to the ``tools`` node (LangGraph
``ToolNode``), then back to ``assess_item`` until a JSON finding is produced.
"""

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
    """Best-effort parse of a JSON object from model output.

    Tries a full-string ``json.loads`` first, then falls back to the first
    ``{…}`` substring. Models occasionally wrap JSON in prose despite
    instructions; this keeps the assess loop resilient.

    Args:
        text: Raw assistant message content.

    Returns:
        Parsed dict, or ``None`` if no valid JSON object is found.
    """
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
    """Clamp a free-form status string to the allowed ``FindingStatus`` set.

    Args:
        value: Raw status from model JSON (may be missing or misspelled).

    Returns:
        One of ``pass|fail|partial|error|skipped``; defaults to ``error``.
    """
    allowed = {"pass", "fail", "partial", "error", "skipped"}
    status = (value or "error").strip().lower()
    return status if status in allowed else "error"


class AuditorGraph:
    """Compile and run the PostgreSQL checklist audit StateGraph.

    Holds:

    * ``model`` — chat model with tools bound (used during assessment)
    * ``plain_model`` — same LiteLLM model without tools (finalize summary)
    * ``tool_node`` — executes tool calls requested by the model
    * ``graph`` — compiled LangGraph runnable (``ainvoke`` / ``astream_events``)
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize models, tools, and compile the graph.

        Args:
            settings: Optional settings override for tests or multi-tenant use.
        """
        self.settings = settings or get_settings()
        self.tools = _all_tools()
        # Tool-calling model for the assess loop.
        self.model = build_chat_model(self.settings).bind_tools(self.tools)
        # No tools for the executive summary (avoids accidental tool calls).
        self.plain_model = build_chat_model(self.settings)
        self.tool_node = ToolNode(self.tools)
        self.graph = self._build()

    def _build(self):
        """Wire nodes and edges into a compiled LangGraph.

        Returns:
            A compiled graph supporting ``ainvoke`` and ``astream_events``.
        """
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
        # After tools execute, return to assess_item so the model can judge.
        graph.add_edge("tools", "assess_item")
        graph.add_edge("finalize", END)
        return graph.compile()

    async def load_checklist(self, state: AuditorState) -> dict[str, Any]:
        """Node: parse the Markdown checklist and initialize run state.

        Reloads the checklist from disk on every run so operators can edit
        ``CHECKLIST_PATH`` without restarting the process. Seeds ``pending_ids``
        in document order and injects ``SYSTEM_PROMPT``.

        Args:
            state: Incoming state (expects ``user_request`` and/or messages).

        Returns:
            Partial state update with requirements, queue, and system message.
        """
        checklist = load_checklist(self.settings.checklist_path)
        req_map: dict[str, Requirement] = checklist.by_id()
        user_request = state.get("user_request") or ""
        if not user_request:
            # Recover the latest human turn if the API only seeded messages.
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
        """Node: dequeue the next requirement id to assess.

        Args:
            state: Current state containing ``pending_ids``.

        Returns:
            ``current_id`` set to the next id, or ``None`` when the queue is
            empty (signals ``finalize`` via ``route_after_select``). Also
            returns the remaining ``pending_ids``.
        """
        pending = list(state.get("pending_ids") or [])
        if not pending:
            return {"current_id": None}
        current = pending.pop(0)
        return {"current_id": current, "pending_ids": pending}

    def route_after_select(
        self, state: AuditorState
    ) -> Literal["assess_item", "finalize"]:
        """Conditional edge: assess when a requirement is selected, else finish.

        Args:
            state: State after ``select_next``.

        Returns:
            ``assess_item`` if ``current_id`` is set; otherwise ``finalize``.
        """
        return "assess_item" if state.get("current_id") else "finalize"

    async def assess_item(self, state: AuditorState) -> dict[str, Any]:
        """Node: assess the current checklist requirement with tools + LLM.

        Behavior branches:

        1. **Invalid current_id** — record an error finding and clear current
           to avoid infinite loops.
        2. **Last message is a final AI JSON answer** — parse it into a
           ``Finding`` without another model call (idempotent path).
        3. **Continuing after tools** — invoke the model on the existing
           transcript (no new assessment prompt).
        4. **Fresh item** — append ``ASSESS_PROMPT`` for this requirement, then
           invoke the model.
        5. **Model returns tool_calls** — return those messages; router sends
           control to the ``tools`` node.
        6. **Model returns JSON** — store a ``Finding`` and a short
           ``Recorded …`` marker message.

        Args:
            state: Graph state with ``current_id``, ``requirements``, messages.

        Returns:
            Partial update with new messages and/or a findings entry.
        """
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

        # Safety path: if we re-enter with a completed AI JSON answer already
        # present, record the finding without calling the model again.
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

        # After ToolNode, last message is ToolMessage — continue the turn.
        continuing = isinstance(last, ToolMessage) or (
            isinstance(last, AIMessage) and bool(getattr(last, "tool_calls", None))
        )

        invoke_messages = messages
        new_messages: list = []
        if not continuing:
            # First visit for this requirement: inject the assessment brief.
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
            # Router will send us to the tools node next.
            return {"messages": new_messages}

        finding = self._finding_from_ai(req_id, requirements[req_id], response)
        new_messages.append(
            AIMessage(content=f"Recorded {req_id}: {finding.status}", name="auditor")
        )
        return {"messages": new_messages, "findings": {req_id: finding}}

    def _recent_prompt_for(self, messages: list, req_id: str) -> bool:
        """Return True if a recent HumanMessage mentions ``req_id``.

        Walks backwards through the last ~20 messages, stopping at a previous
        ``Recorded …`` marker so we do not attribute an older prompt to the
        current requirement.

        Args:
            messages: Full transcript.
            req_id: Requirement id to look for (e.g. ``REQ-003``).

        Returns:
            Whether an assessment prompt for this id is present recently.
        """
        for msg in reversed(messages[-20:]):
            if isinstance(msg, HumanMessage) and req_id in str(msg.content):
                return True
            if isinstance(msg, AIMessage) and str(msg.content).startswith("Recorded "):
                break
        return False

    def _finding_from_ai(
        self, req_id: str, req: Requirement, ai: AIMessage
    ) -> Finding:
        """Convert an assistant JSON (or prose) reply into a ``Finding``.

        Args:
            req_id: Requirement identifier.
            req: Full requirement metadata (title/severity/category).
            ai: Assistant message expected to contain assessment JSON.

        Returns:
            Structured ``Finding``. If JSON parsing fails, status becomes
            ``error`` and ``evidence`` falls back to raw assistant text.
        """
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
        """Conditional edge after ``assess_item``.

        Args:
            state: State after the assess node update is merged.

        Returns:
            ``tools`` if the latest AI message requested tool calls; otherwise
            ``select_next`` to continue the checklist (or finish when empty).
        """
        last = (state.get("messages") or [])[-1] if state.get("messages") else None
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            return "tools"
        return "select_next"

    async def finalize(self, state: AuditorState) -> dict[str, Any]:
        """Node: build the Markdown report and an executive summary.

        Renders structured findings first (deterministic), then asks the plain
        (tool-free) model for a short narrative summary. Concatenates both into
        ``report`` for the OpenAI-compatible API response.

        Args:
            state: Completed assessment state with ``findings``.

        Returns:
            Partial update containing ``report`` and a final assistant message.
        """
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
        except Exception as exc:  # noqa: BLE001 — still return the structured report
            summary = f"(Summary generation failed: {exc})"

        final_text = f"{summary}\n\n---\n\n{report}"
        return {
            "report": final_text,
            "messages": [AIMessage(content=final_text)],
        }

    async def arun(self, user_text: str) -> dict[str, Any]:
        """Convenience wrapper: run a full audit for a single user prompt.

        Args:
            user_text: Operator request from Open WebUI / the API.

        Returns:
            Final graph state dict (includes ``report``, ``findings``, etc.).
        """
        initial: AuditorState = {
            "messages": [HumanMessage(content=user_text)],
            "user_request": user_text,
        }
        return await self.graph.ainvoke(initial)


# Process-wide singleton used by the FastAPI layer.
_graph: AuditorGraph | None = None


def get_auditor_graph() -> AuditorGraph:
    """Return a lazily constructed process-wide ``AuditorGraph``.

    Laziness avoids connecting to LiteLLM / loading settings at import time
    (important for unit tests that only exercise parsers).

    Returns:
        Shared ``AuditorGraph`` instance.
    """
    global _graph
    if _graph is None:
        _graph = AuditorGraph()
    return _graph

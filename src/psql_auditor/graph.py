"""LangGraph workflow: load checklist → parallel assess → finalize report.

Control flow (high level)::

    START
      → load_checklist      # parse MD, seed pending_ids
      → assess_parallel     # asyncio fan-out over REQ-* (bounded concurrency)
      → finalize → END      # compact digest → summary + full report

Quality + context policy (unchanged):

* Each requirement uses an **isolated** local message window (no shared transcript).
* Tool outputs truncated; tool rounds capped; then forced JSON decision.
* Finalize LLM sees a compact findings digest; full report stays in the response.

Parallelism:

* Up to ``MAX_PARALLEL_ASSESSMENTS`` requirements assessed concurrently.
* LLM calls overlap; MCP stdio remains serialized under a lock (protocol-safe).
* SSH / other tools may run concurrently across workers.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import REMOVE_ALL_MESSAGES

from psql_auditor.checklist import Requirement, load_checklist
from psql_auditor.config import Settings, get_settings
from psql_auditor.context import (
    compact_findings_for_summary,
    count_tool_rounds,
    truncate_text,
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
    """Collect every LangChain tool bound into the assess-loop model."""
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
    """Compile and run the PostgreSQL checklist audit StateGraph."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize models, tools, and compile the graph."""
        self.settings = settings or get_settings()
        self.tools = _all_tools()
        self.tools_by_name = {t.name: t for t in self.tools}
        self.model = build_chat_model(self.settings).bind_tools(self.tools)
        self.plain_model = build_chat_model(self.settings)
        self.graph = self._build()

    def _build(self):
        """Wire nodes: load → parallel assess → finalize."""
        graph = StateGraph(AuditorState)
        graph.add_node("load_checklist", self.load_checklist)
        graph.add_node("assess_parallel", self.assess_parallel)
        graph.add_node("finalize", self.finalize)

        graph.add_edge(START, "load_checklist")
        graph.add_edge("load_checklist", "assess_parallel")
        graph.add_edge("assess_parallel", "finalize")
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
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                SystemMessage(
                    content=(
                        f"{SYSTEM_PROMPT}\n\n"
                        f"[Parallel audit: {len(checklist.ids())} requirements, "
                        f"concurrency={self.settings.max_parallel_assessments}]"
                    )
                ),
            ],
        }

    async def assess_parallel(self, state: AuditorState) -> dict[str, Any]:
        """Node: assess all pending requirements concurrently.

        Each worker runs an isolated ReAct loop (private message list). A
        semaphore limits how many assessments run at once to protect LiteLLM
        rate limits and keep MCP queue depth reasonable.

        Args:
            state: State after ``load_checklist``.

        Returns:
            Merged ``findings`` for every requirement id.
        """
        requirements = state.get("requirements") or {}
        pending = list(state.get("pending_ids") or requirements.keys())
        user_request = state.get("user_request") or "(none)"
        limit = max(1, self.settings.max_parallel_assessments)
        sem = asyncio.Semaphore(limit)

        async def _worker(req_id: str) -> Finding:
            async with sem:
                try:
                    return await self._assess_one_isolated(
                        req_id=req_id,
                        requirement=requirements[req_id],
                        user_request=user_request,
                    )
                except Exception as exc:  # noqa: BLE001
                    return Finding(
                        requirement_id=req_id,
                        title=requirements[req_id].title
                        if req_id in requirements
                        else "",
                        status="error",
                        severity=requirements[req_id].severity
                        if req_id in requirements
                        else "",
                        category=requirements[req_id].category
                        if req_id in requirements
                        else "",
                        evidence=f"Parallel assess failed: {type(exc).__name__}: {exc}",
                    )

        # Skip unknown ids defensively.
        work_ids = [rid for rid in pending if rid in requirements]
        findings_list = await asyncio.gather(*[_worker(rid) for rid in work_ids])
        findings = {f.requirement_id: f for f in findings_list}

        summary_line = (
            f"Parallel assessment complete: {len(findings)} requirements "
            f"(concurrency={limit})."
        )
        return {
            "findings": findings,
            "pending_ids": [],
            "current_id": None,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                AIMessage(content=summary_line, name="auditor"),
            ],
        }

    async def _assess_one_isolated(
        self,
        req_id: str,
        requirement: Requirement,
        user_request: str,
    ) -> Finding:
        """Run a full ReAct assess loop for one requirement in a private window.

        Does not touch shared graph ``messages`` — safe under asyncio.gather.
        """
        messages: list = [
            SystemMessage(
                content=(
                    f"{SYSTEM_PROMPT}\n\n"
                    f"[Isolated worker for {req_id}. Focus only on this requirement.]"
                )
            ),
            HumanMessage(
                content=ASSESS_PROMPT.format(
                    user_request=user_request,
                    requirement_block=requirement.to_prompt_block(),
                )
            ),
        ]

        max_rounds = self.settings.max_tool_rounds_per_item
        for _ in range(max_rounds + 1):
            rounds = count_tool_rounds(messages)
            if rounds >= max_rounds:
                messages.append(HumanMessage(content=FORCE_DECIDE_PROMPT))
                response = await self.plain_model.ainvoke(messages)
                return self._finding_from_ai(req_id, requirement, response)

            response = await self.model.ainvoke(messages)
            messages.append(response)

            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                return self._finding_from_ai(req_id, requirement, response)

            # Execute this turn's tools concurrently (MCP still serializes internally).
            tool_messages = await self._execute_tool_calls(tool_calls)
            messages.extend(tool_messages)

        # Exhausted loop without a clean JSON turn — force decide.
        messages.append(HumanMessage(content=FORCE_DECIDE_PROMPT))
        response = await self.plain_model.ainvoke(messages)
        return self._finding_from_ai(req_id, requirement, response)

    async def _execute_tool_calls(self, tool_calls: list[dict[str, Any]]) -> list[ToolMessage]:
        """Run tool calls for one model turn, optionally in parallel."""

        async def _one(tc: dict[str, Any]) -> ToolMessage:
            name = tc.get("name") or ""
            args = tc.get("args") or {}
            call_id = tc.get("id") or name
            tool = self.tools_by_name.get(name)
            if tool is None:
                content = f"Tool error: unknown tool '{name}'"
            else:
                try:
                    raw = await tool.ainvoke(args)
                    content = truncate_text(
                        str(raw),
                        self.settings.max_tool_output_chars,
                        "tool",
                    )
                except Exception as exc:  # noqa: BLE001
                    content = f"Tool error: {type(exc).__name__}: {exc}"
            return ToolMessage(content=content, tool_call_id=call_id, name=name)

        return list(await asyncio.gather(*[_one(tc) for tc in tool_calls]))

    def _finding_from_ai(
        self, req_id: str, req: Requirement, ai: AIMessage
    ) -> Finding:
        """Convert an assistant JSON (or prose) reply into a Finding."""
        data = _extract_json(str(ai.content or "")) or {}
        finding = Finding(
            requirement_id=req_id,
            title=req.title,
            status=_normalize_status(data.get("status")),  # type: ignore[arg-type]
            severity=req.severity,
            category=req.category,
            evidence=str(data.get("evidence") or ai.content or ""),
            remediation=str(data.get("remediation") or ""),
            notes=str(data.get("notes") or ""),
        )
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
        return finding

    async def finalize(self, state: AuditorState) -> dict[str, Any]:
        """Node: executive summary from a compact digest + full Markdown report."""
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

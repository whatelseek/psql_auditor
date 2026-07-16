"""LangGraph workflow: load checklist → parallel fill report cells → finalize.

Control flow::

    START
      → load_checklist
      → assess_parallel   # per REQ: gather evidence → fill 3 cells
      → finalize → END

Fixed report format:

* Checklist supplies immutable cells: ID, title, category, severity, pass criteria.
* Model fills only: **status**, **observation**, **recommendation**.

Token strategy:

1. Evidence phase — short tool loop; keep only truncated evidence text.
2. Fill phase — tiny no-tool prompt (requirement + evidence → JSON cells).
3. Assembly — deterministic Markdown template (no LLM rewriting of checklist).
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
    EVIDENCE_FORCE_PROMPT,
    EVIDENCE_PROMPT,
    EVIDENCE_SYSTEM_PROMPT,
    FILL_CELL_PROMPT,
    FILL_SYSTEM_PROMPT,
    FINALIZE_PROMPT,
)
from psql_auditor.state import AuditorState, Finding, render_report
from psql_auditor.tools.mcp_client import get_mcp_tools
from psql_auditor.tools.ssh import get_ssh_tools


def _all_tools() -> list:
    """Collect LangChain tools for the evidence-gathering phase."""
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
    """Compile and run the fixed-format PostgreSQL audit StateGraph."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize models, tools, and compile the graph."""
        self.settings = settings or get_settings()
        self.tools = _all_tools()
        self.tools_by_name = {t.name: t for t in self.tools}
        # Tool-calling model: evidence only.
        self.evidence_model = build_chat_model(self.settings).bind_tools(self.tools)
        # No tools: fill report cells + finalize summary.
        self.fill_model = build_chat_model(self.settings)
        self.graph = self._build()

    def _build(self):
        """Wire nodes: load → parallel cell fill → finalize."""
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
        """Node: parse checklist and seed the fixed report row list."""
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
                        f"Fixed-format audit: {len(checklist.ids())} requirement rows. "
                        f"Model fills Status/Observation/Recommendation only. "
                        f"Parallelism={self.settings.max_parallel_assessments}."
                    )
                ),
            ],
        }

    async def assess_parallel(self, state: AuditorState) -> dict[str, Any]:
        """Node: fill report cells for all requirements in parallel."""
        requirements = state.get("requirements") or {}
        pending = list(state.get("pending_ids") or requirements.keys())
        user_request = state.get("user_request") or "(none)"
        limit = max(1, self.settings.max_parallel_assessments)
        sem = asyncio.Semaphore(limit)

        async def _worker(req_id: str) -> Finding:
            async with sem:
                try:
                    return await self._fill_requirement_cells(
                        req_id=req_id,
                        requirement=requirements[req_id],
                        user_request=user_request,
                    )
                except Exception as exc:  # noqa: BLE001
                    req = requirements.get(req_id)
                    return Finding(
                        requirement_id=req_id,
                        title=req.title if req else "",
                        status="error",
                        severity=req.severity if req else "",
                        category=req.category if req else "",
                        pass_criteria=req.pass_criteria if req else "",
                        evidence=f"Cell fill failed: {type(exc).__name__}: {exc}",
                        remediation="",
                    )

        work_ids = [rid for rid in pending if rid in requirements]
        findings_list = await asyncio.gather(*[_worker(rid) for rid in work_ids])
        findings = {f.requirement_id: f for f in findings_list}

        return {
            "findings": findings,
            "pending_ids": [],
            "current_id": None,
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                AIMessage(
                    content=(
                        f"Filled {len(findings)} report rows "
                        f"(concurrency={limit})."
                    ),
                    name="auditor",
                ),
            ],
        }

    async def _fill_requirement_cells(
        self,
        req_id: str,
        requirement: Requirement,
        user_request: str,
    ) -> Finding:
        """Gather evidence, then fill status/observation/recommendation cells.

        The fill-phase prompt intentionally excludes the tool transcript — only
        a truncated evidence blob is passed — to keep token usage low and the
        context window safe.
        """
        evidence = await self._gather_evidence(req_id, requirement, user_request)
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
        return self._cells_to_finding(req_id, requirement, response, evidence)

    async def _gather_evidence(
        self,
        req_id: str,
        requirement: Requirement,
        user_request: str,
    ) -> str:
        """Run a short tool loop and return compact evidence text only."""
        messages: list = [
            SystemMessage(content=EVIDENCE_SYSTEM_PROMPT),
            HumanMessage(
                content=EVIDENCE_PROMPT.format(
                    user_request=user_request,
                    requirement_block=requirement.to_prompt_block(),
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

            tool_messages = await self._execute_tool_calls(tool_calls)
            messages.extend(tool_messages)
            for tm in tool_messages:
                chunks.append(f"[{tm.name}] {tm.content}")

        return "\n---\n".join(c.strip() for c in chunks if c and c.strip())

    async def _execute_tool_calls(
        self, tool_calls: list[dict[str, Any]]
    ) -> list[ToolMessage]:
        """Run tool calls for one evidence turn (parallel where safe)."""

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

    def _cells_to_finding(
        self,
        req_id: str,
        req: Requirement,
        ai: AIMessage,
        fallback_evidence: str,
    ) -> Finding:
        """Map fill-phase JSON into a Finding; checklist fields stay fixed."""
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
        finding = Finding(
            requirement_id=req_id,
            title=req.title,
            status=_normalize_status(data.get("status")),  # type: ignore[arg-type]
            severity=req.severity,
            category=req.category,
            pass_criteria=req.pass_criteria,
            evidence=observation,
            remediation=recommendation,
            notes=str(data.get("notes") or ""),
        )
        finding.evidence = truncate_text(
            finding.evidence or "",
            self.settings.max_finding_evidence_chars,
            "observation",
        )
        finding.remediation = truncate_text(
            finding.remediation or "",
            min(self.settings.max_finding_evidence_chars, 1200),
            "recommendation",
        )
        return finding

    async def finalize(self, state: AuditorState) -> dict[str, Any]:
        """Assemble fixed report; LLM writes a short executive summary only."""
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
        try:
            response = await self.fill_model.ainvoke(
                [
                    SystemMessage(
                        content=(
                            "You write short executive summaries for fixed-format "
                            "PostgreSQL audit reports."
                        )
                    ),
                    HumanMessage(content=FINALIZE_PROMPT.format(report=digest)),
                ]
            )
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

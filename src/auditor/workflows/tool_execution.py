"""Tool-call execution with progress events and evidence logging."""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.messages import ToolMessage

from auditor.context import truncate_text
from auditor.evidence_store import EvidenceStore
from auditor.progress import emit_tool_call, emit_tool_result
from auditor.workflows.helpers import _tool_result_looks_failed
from auditor.workflows.protocols import AuditRuntime


async def execute_tool_calls(
    runtime: AuditRuntime,
    tool_calls: list[dict[str, Any]],
    *,
    framework_id: str = "",
    req_id: str = "",
    requirement_title: str = "",
    store: EvidenceStore | None = None,
) -> list[ToolMessage]:
    """Execute parallel tool calls from the evidence model response.

    Emits progress events, logs to the evidence store, and updates playbook
    memory on success.

    Args:
        tool_calls: LangChain tool call dicts from the model.
        framework_id: Framework id for logging and memory.
        req_id: Requirement id for logging and memory.
        requirement_title: Human checklist title for live UI labels.
        store: Optional evidence store.

    Returns:
        ``ToolMessage`` list in call order for appending to chat history.
    """

    async def _one(tc: dict[str, Any]) -> ToolMessage:
        """Invoke a single tool call and return its ``ToolMessage``."""
        name = tc.get("name") or ""
        args = tc.get("args") or {}
        call_id = tc.get("id") or name
        emit_tool_call(
            name,
            args,
            call_id=str(call_id),
            requirement_id=req_id,
            requirement_title=requirement_title,
            framework_id=framework_id,
        )
        error: str | None = None
        full_result = ""
        tool = runtime.tools_by_name.get(name)
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
                    runtime.settings.max_tool_output_chars,
                    "tool",
                )
            except Exception as exc:  # noqa: BLE001
                full_result = f"Tool error: {type(exc).__name__}: {exc}"
                error = full_result
                content = full_result
        emit_tool_result(
            name,
            full_result,
            call_id=str(call_id),
            requirement_id=req_id,
            requirement_title=requirement_title,
            framework_id=framework_id,
            error=error,
        )
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
            runtime.playbooks is not None
            and runtime.settings.memory_learn
            and req_id
            and not error
            and not _tool_result_looks_failed(full_result)
        ):
            runtime.playbooks.remember_tool(
                framework_id,
                req_id,
                name,
                args if isinstance(args, dict) else {"value": args},
                success=True,
            )
        return ToolMessage(content=content, tool_call_id=call_id, name=name)

    return list(await asyncio.gather(*[_one(tc) for tc in tool_calls]))

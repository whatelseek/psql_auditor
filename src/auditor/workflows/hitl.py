"""HITL gate, skip/retry interrupts, and post-assess/HITL routers."""

from __future__ import annotations

from typing import Any, Literal

from langchain_core.messages import AIMessage
from langgraph.types import interrupt

from auditor.checklist import Requirement
from auditor.hitl import (
    HitlDecision,
    build_hitl_prompt,
    interpret_hitl_decision,
)
from auditor.state import AuditorState, Finding
from auditor.workflows.helpers import _as_finding, _hitl_candidates
from auditor.workflows.protocols import AuditRuntime

def route_after_assess(runtime: AuditRuntime, state: AuditorState
) -> Literal["reconnect_session", "human_gate", "finalize"]:
    """Reconnect on transport errors; otherwise ask the human about failures."""
    pending = state.get("pending_ids") or []
    retry_count = int(state.get("retry_count") or 0)
    max_retries = runtime.settings.max_session_retries
    if pending and retry_count < max_retries:
        return "reconnect_session"
    if runtime.settings.hitl_enabled and _hitl_candidates(state):
        return "human_gate"
    return "finalize"

def route_after_hitl(runtime: AuditRuntime, state: AuditorState
) -> Literal["assess_parallel", "human_gate", "finalize"]:
    """After skip/retry: reassess, ask about the next failure, or finalize."""
    pending = state.get("pending_ids") or []
    if pending:
        return "assess_parallel"
    if runtime.settings.hitl_enabled and _hitl_candidates(state):
        return "human_gate"
    return "finalize"

async def human_gate(runtime: AuditRuntime, state: AuditorState) -> dict[str, Any]:
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
    store = runtime._store_from_state(state)

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

    raw_reply = interrupt(payload)
    decision = await interpret_hitl_decision(
        raw_reply,
        llm=runtime.fill_model,
        requirement_id=req_id,
        requirement_title=requirement.title,
        why=finding.evidence or finding.notes or "",
        candidates=candidates,
    )
    if decision.action == "unknown":
        retry_prompt = (
            "I didn't understand that reply "
            "(and the model could not classify it).\n\n"
            "Please answer with **skip**, **retry**, **skip all**, or **retry all**.\n\n"
            f"{prompt}"
        )
        raw_reply = interrupt({**payload, "prompt": retry_prompt})
        decision = await interpret_hitl_decision(
            raw_reply,
            llm=runtime.fill_model,
            requirement_id=req_id,
            requirement_title=requirement.title,
            why=finding.evidence or finding.notes or "",
            candidates=candidates,
        )
    if decision.action == "unknown":
        # Last resort: continue the audit rather than deadlocking the chat.
        decision = HitlDecision(
            action="skip_all", raw=decision.raw, source="llm"
        )

    skipped = list(state.get("hitl_skipped") or [])
    via = (
        " (LLM interpreted reply)"
        if decision.source == "llm"
        else ""
    )

    if decision.action == "skip_all":
        updates: dict[str, Finding] = {}
        for rid in candidates:
            updates[rid] = runtime._skipped_finding(
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
                        f"Operator skipped {len(candidates)} failed "
                        f"requirement(s){via}."
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
                        f"failed requirement(s){via}."
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
                req_id: runtime._skipped_finding(
                    finding,
                    reason="Skipped by operator after failed assessment.",
                )
            },
            "hitl_skipped": skipped,
            "pending_ids": [],
            "awaiting_hitl": False,
            "messages": [
                AIMessage(
                    content=f"Operator skipped `{req_id}`{via}.",
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
                content=f"Operator requested retry for `{req_id}`{via}.",
                name="auditor",
            )
        ],
    }

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


skipped_finding = _skipped_finding

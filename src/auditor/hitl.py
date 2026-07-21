"""Human-in-the-loop helpers for failed requirement assessments.

When a requirement cannot be audited, the graph interrupts and asks the
operator to **skip** or **try again**. Open WebUI resumes via the next chat
message (same pattern as LangGraph interrupt + Command(resume=…)).

Clear replies are parsed with regex; otherwise the LLM interprets intent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from auditor.checklist import Requirement
from auditor.state import Finding

HitlAction = Literal["skip", "retry", "skip_all", "retry_all", "unknown"]
PauseKind = Literal["hitl", "intake", "continue"]

# Visible marker embedded in assistant replies so the next chat turn can resume.
HITL_MARKER_RE = re.compile(
    r"\[AUDIT_HITL:(?P<thread>[A-Za-z0-9._:-]+)\]",
    re.IGNORECASE,
)

# Most recent pause marker wins — CONTINUE / HITL / INTAKE.
PAUSE_MARKER_RE = re.compile(
    r"\[AUDIT_(?P<kind>HITL|INTAKE|CONTINUE):(?P<thread>[A-Za-z0-9._:-]+)\]",
    re.IGNORECASE,
)

CONTINUE_REPLY_RE = re.compile(
    r"\b(continue|resume|продолж\w*|далее)\b",
    re.IGNORECASE,
)

_VALID_ACTIONS = frozenset({"skip", "retry", "skip_all", "retry_all"})


@dataclass(frozen=True, slots=True)
class HitlDecision:
    """Parsed operator decision for a paused requirement."""

    action: HitlAction
    raw: str
    source: Literal["regex", "llm", "explicit"] = "regex"


def extract_hitl_thread_id(messages: list[Any]) -> str | None:
    """Find ``[AUDIT_HITL:<thread>]`` only when it is the newest pause marker."""
    resolved = resolve_pause_resume(messages)
    if resolved and resolved[0] == "hitl":
        return resolved[1]
    return None


def resolve_pause_resume(messages: list[Any]) -> tuple[PauseKind, str] | None:
    """Return ``(kind, thread_id)`` from the newest assistant pause marker.

    Scans chat history newest-first and uses the last ``AUDIT_HITL`` /
    ``AUDIT_INTAKE`` marker in that message so a HITL pause after intake is
    not overridden by older intake markers still present in history.
    """
    for msg in reversed(messages):
        role, content = _msg_role_content(msg)
        if role not in ("assistant", "system") or not content:
            continue
        matches = list(PAUSE_MARKER_RE.finditer(str(content)))
        if not matches:
            continue
        m = matches[-1]
        kind = m.group("kind").lower()
        if kind in ("hitl", "intake", "continue"):
            return kind, m.group("thread")  # type: ignore[return-value]
    return None


def format_continue_assistant_message(prompt: str, thread_id: str) -> str:
    """Marker so the operator can resume an interrupted mid-assess run."""
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_CONTINUE:{thread_id}]\n"
        f"_Audit interrupted. Reply **continue** to resume from checkpoint._\n"
    )


def is_continue_reply(text: str) -> bool:
    return bool(CONTINUE_REPLY_RE.search(str(text or "")))


def parse_hitl_decision(text: Any) -> HitlDecision:
    """Parse skip / retry (and all variants) from free-text user reply."""
    if isinstance(text, dict):
        action = str(text.get("action") or text.get("decision") or "").strip().lower()
        raw = str(text.get("text") or text.get("raw") or action)
        if action in _VALID_ACTIONS:
            return HitlDecision(action=action, raw=raw, source="explicit")  # type: ignore[arg-type]
        text = raw

    # LangGraph may resume with a list of messages from some clients.
    if isinstance(text, list):
        parts: list[str] = []
        for item in text:
            if isinstance(item, dict):
                parts.append(str(item.get("content") or ""))
            else:
                parts.append(str(getattr(item, "content", item) or ""))
        text = "\n".join(parts)

    raw = str(text or "").strip()
    # Strip markdown emphasis so **skip all** still matches.
    normalized = re.sub(r"[*_`]+", "", raw.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()

    if not normalized:
        return HitlDecision(action="unknown", raw=raw)

    if re.search(r"\bskip\s+all\b", normalized) or normalized in {"sa", "skipall"}:
        return HitlDecision(action="skip_all", raw=raw)
    if re.search(r"\b(retry|try)\s+all\b", normalized) or normalized in {
        "ra",
        "retryall",
    }:
        return HitlDecision(action="retry_all", raw=raw)
    if re.search(r"\b(skip|skipped|ignore|pass)\b", normalized) or normalized in {
        "s",
        "no",
        "n",
    }:
        return HitlDecision(action="skip", raw=raw)
    if re.search(
        r"\b(retry|try again|try|recheck|rerun|again)\b",
        normalized,
    ) or normalized in {"r", "yes", "y"}:
        return HitlDecision(action="retry", raw=raw)

    return HitlDecision(action="unknown", raw=raw)


async def interpret_hitl_decision(
    text: Any,
    *,
    llm: BaseChatModel,
    requirement_id: str = "",
    requirement_title: str = "",
    why: str = "",
    candidates: list[str] | None = None,
) -> HitlDecision:
    """Regex-parse first; if unclear, ask the LLM to choose an action."""
    decision = parse_hitl_decision(text)
    if decision.action != "unknown":
        return decision

    raw = decision.raw
    if not raw.strip():
        return decision

    pending = ", ".join(candidates or ([requirement_id] if requirement_id else []))
    system = (
        "You classify an operator reply for a paused security audit (HITL).\n"
        "Choose exactly one action:\n"
        "- skip — skip only the current failed requirement and continue\n"
        "- retry — retry only the current failed requirement\n"
        "- skip_all — skip all remaining failed requirements and continue\n"
        "- retry_all — retry all remaining failed requirements\n"
        "Reply with ONLY the action token (skip|retry|skip_all|retry_all), no punctuation."
    )
    human = (
        f"Current requirement: {requirement_id or '—'} "
        f"({requirement_title or '—'})\n"
        f"Why paused: {(why or '—')[:800]}\n"
        f"Remaining failed ids: {pending or '—'}\n\n"
        f"Operator reply:\n{raw[:1500]}"
    )
    try:
        response = await llm.ainvoke(
            [SystemMessage(content=system), HumanMessage(content=human)]
        )
        content = getattr(response, "content", response)
        if isinstance(content, list):
            content = " ".join(
                str(part.get("text") if isinstance(part, dict) else part)
                for part in content
            )
        token = re.sub(r"[*_`]+", "", str(content or "").strip().lower())
        token = re.sub(r"\s+", "_", token.split()[0]) if token.split() else ""
        # Accept "skip all" style from the model too
        llm_parsed = parse_hitl_decision(str(content or ""))
        if llm_parsed.action != "unknown":
            return HitlDecision(
                action=llm_parsed.action, raw=raw, source="llm"
            )
        if token in _VALID_ACTIONS:
            return HitlDecision(action=token, raw=raw, source="llm")  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 — fall through to unknown
        return HitlDecision(action="unknown", raw=raw, source="llm")

    return HitlDecision(action="unknown", raw=raw, source="llm")


def _msg_role_content(msg: Any) -> tuple[Any, Any]:
    role = getattr(msg, "role", None)
    content = getattr(msg, "content", None)
    if isinstance(msg, dict):
        role = msg.get("role")
        content = msg.get("content")
    return role, content


def build_hitl_prompt(
    *,
    framework_id: str,
    requirement: Requirement,
    finding: Finding,
    evidence_dir: str | None = None,
) -> str:
    """Human-readable interrupt prompt for one failed requirement."""
    why = (finding.evidence or finding.notes or "No evidence collected.").strip()
    recommendation = (
        finding.remediation or _default_recommendation(finding, requirement)
    ).strip()
    lines = [
        f"## Could not audit `{requirement.id}`",
        "",
        f"**Framework:** `{framework_id}`",
        f"**Requirement:** {requirement.title}",
        f"**Category:** {requirement.category or '—'} | **Severity:** {requirement.severity or '—'}",
        "",
        "### Why",
        why,
        "",
        "### Pass criteria",
        requirement.pass_criteria or "—",
        "",
        "### How to verify (checklist)",
        requirement.how_to_verify or "—",
        "",
        "### Recommendations",
        recommendation,
    ]
    if evidence_dir:
        lines.extend(["", f"**Evidence folder:** `{evidence_dir}`"])
    lines.extend(
        [
            "",
            "### What should I do?",
            "Reply with one of:",
            "- **skip** — mark this requirement as skipped and continue",
            "- **retry** — try auditing this requirement again",
            "- **skip all** — skip all remaining failed requirements",
            "- **retry all** — retry all remaining failed requirements",
        ]
    )
    return "\n".join(lines)


def format_hitl_assistant_message(prompt: str, thread_id: str) -> str:
    """Wrap interrupt prompt with a resume marker for the chat API."""
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_HITL:{thread_id}]\n"
        f"_Paused for human decision. Your next message resumes this audit._\n"
    )


def _default_recommendation(finding: Finding, requirement: Requirement) -> str:
    blob = f"{finding.evidence} {finding.notes}".lower()
    tips: list[str] = []
    if "ssh" in blob or "not configured" in blob:
        tips.append(
            "Check `SSH_HOST` / credentials and confirm the host is reachable from the agent."
        )
    if "mcp" in blob or "postgres" in blob or "connection" in blob:
        tips.append(
            "Check `PG_*` / `DATABASE_URL` and that antonorlov/mcp-postgres-server can connect."
        )
    if "timeout" in blob:
        tips.append("Increase timeouts or reduce load on the target, then retry.")
    if "permission" in blob or "denied" in blob:
        tips.append(
            "Grant the audit user read access to the needed files/views, then retry."
        )
    if not tips:
        tips.append(
            "Fix the underlying access/config issue described above, then reply **retry**; "
            "or reply **skip** if this check is out of scope."
        )
    if requirement.how_to_verify:
        tips.append(f"Manual check: {requirement.how_to_verify}")
    return "\n".join(f"- {t}" for t in tips)


def interrupt_payload_to_prompt(value: Any) -> str:
    """Extract display text from a LangGraph Interrupt value."""
    if isinstance(value, dict):
        return str(value.get("prompt") or value.get("message") or value)
    return str(value)

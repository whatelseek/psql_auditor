"""Human-in-the-loop helpers for failed requirement assessments.

When a requirement cannot be audited (SSH/MCP failure, timeout, etc.), the
LangGraph checklist pauses and asks the operator to **skip** or **try again**.
Open WebUI and similar chat frontends resume via the next user message using
the same pattern as LangGraph ``interrupt`` + ``Command(resume=…)``.

Pipeline role:
    Provides pause/resume markers (``[AUDIT_HITL:<thread>]``), decision parsing
    (regex with LLM fallback), and formatted interrupt prompts so the graph can
    continue, skip, or retry failed requirements without losing checkpoint state.

Key entry points:
    :func:`build_hitl_prompt` — human-readable interrupt body for one REQ.
    :func:`format_hitl_assistant_message` — embed resume marker in assistant reply.
    :func:`parse_hitl_decision` / :func:`interpret_hitl_decision` — map user text to action.
    :func:`resolve_pause_resume` — detect newest pause kind from chat history.
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
# Supports both visible markers:
#   [AUDIT_INTAKE:thread]
# and hidden HTML-comment markers:
#   <!-- AUDIT_INTAKE:thread -->
# and markdown comment markers:
#   [//]: # (AUDIT_INTAKE:thread)
PAUSE_MARKER_RE = re.compile(
    r"(?:"
    r"\[AUDIT_(?P<kind>HITL|INTAKE|CONTINUE):(?P<thread>[A-Za-z0-9._:-]+)\]"
    r"|<!--\s*AUDIT_(?P<h_kind>HITL|INTAKE|CONTINUE):(?P<h_thread>[A-Za-z0-9._:-]+)\s*-->"
    r"|\[//\]:\s*#\s*\(\s*AUDIT_(?P<m_kind>HITL|INTAKE|CONTINUE):(?P<m_thread>[A-Za-z0-9._:-]+)\s*\)"
    r")",
    re.IGNORECASE,
)

CONTINUE_REPLY_RE = re.compile(
    r"\b(continue|resume|продолж\w*|далее)\b",
    re.IGNORECASE,
)

_VALID_ACTIONS = frozenset({"skip", "retry", "skip_all", "retry_all"})


@dataclass(frozen=True, slots=True)
class HitlDecision:
    """Parsed operator decision for a paused requirement.

    Attributes:
        action: One of ``skip``, ``retry``, ``skip_all``, ``retry_all``, or
            ``unknown`` when intent could not be determined.
        raw: Original operator text before normalization.
        source: How the action was resolved: ``regex``, ``llm``, or ``explicit``
            (structured resume payload from the client).
    """

    action: HitlAction
    raw: str
    source: Literal["regex", "llm", "explicit"] = "regex"


def resolve_pause_resume(messages: list[Any]) -> tuple[PauseKind, str] | None:
    """Return ``(kind, thread_id)`` from the newest assistant pause marker.

    Scans chat history newest-first and uses the last ``AUDIT_HITL`` /
    ``AUDIT_INTAKE`` / ``AUDIT_CONTINUE`` marker in each assistant message so
    a HITL pause after intake is not overridden by older intake markers still
    present in the same or prior messages.

    Args:
        messages: Chat history (newest message typically last in the list).

    Returns:
        Tuple of pause kind (``hitl``, ``intake``, or ``continue``) and thread
        id, or ``None`` when no pause marker is found.
    """
    for msg in reversed(messages):
        role, content = _msg_role_content(msg)
        if role not in ("assistant", "system") or not content:
            continue
        matches = list(PAUSE_MARKER_RE.finditer(str(content)))
        if not matches:
            continue
        m = matches[-1]
        kind = str(
            m.group("kind") or m.group("h_kind") or m.group("m_kind") or ""
        ).lower()
        thread = str(
            m.group("thread") or m.group("h_thread") or m.group("m_thread") or ""
        )
        if kind in ("hitl", "intake", "continue"):
            return kind, thread  # type: ignore[return-value]
    return None


def format_continue_assistant_message(prompt: str, thread_id: str) -> str:
    """Format assistant message with a continue marker for mid-assess resume.

    Used when a long-running audit is interrupted (e.g. timeout) and the
    operator must reply **continue** to resume from the LangGraph checkpoint.

    Args:
        prompt: Human-readable status or instruction text.
        thread_id: LangGraph thread id embedded in ``[AUDIT_CONTINUE:…]``.

    Returns:
        Markdown string with prompt, separator, marker, and resume hint.
    """
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_CONTINUE:{thread_id}]\n"
        f"_Audit interrupted. Reply **continue** to resume from checkpoint._\n"
    )


def is_continue_reply(text: str) -> bool:
    """Return True when operator text is a continue/resume command.

    Matches English and Russian variants (e.g. "continue", "resume",
    "продолжить", "далее") via :data:`CONTINUE_REPLY_RE`.

    Args:
        text: Raw operator message.

    Returns:
        ``True`` if the message requests resuming an interrupted audit.
    """
    return bool(CONTINUE_REPLY_RE.search(str(text or "")))


def parse_hitl_decision(text: Any) -> HitlDecision:
    """Parse skip / retry (and all variants) from free-text user reply.

    Handles structured dict payloads (``action`` / ``decision`` keys), lists
    of message fragments, and normalized free text with markdown stripped.

    Args:
        text: Operator reply, resume payload dict, or message list.

    Returns:
        :class:`HitlDecision` with ``action`` set to a known token or
        ``unknown`` when no pattern matches.
    """
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
    """Regex-parse first; if unclear, ask the LLM to choose an action.

    Args:
        text: Operator reply (same formats as :func:`parse_hitl_decision`).
        llm: Chat model for ambiguous replies.
        requirement_id: Current failed REQ id (context for the classifier).
        requirement_title: Human title of the requirement.
        why: Short explanation of why the audit paused.
        candidates: Remaining failed requirement ids for bulk actions.

    Returns:
        :class:`HitlDecision` with ``source`` ``regex``, ``llm``, or
        ``explicit``. Returns ``unknown`` when both parsers fail.
    """
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
    """Extract ``(role, content)`` from a dict or LangChain message object.

    Args:
        msg: Chat message as dict or object with optional ``role``/``content``.

    Returns:
        Tuple of role and content (either may be ``None``).
    """
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
    """Build human-readable interrupt prompt for one failed requirement.

    Includes why the check failed, pass criteria, checklist verification steps,
    contextual remediation tips, and explicit skip/retry instructions.

    Args:
        framework_id: Active framework id (e.g. ``ubuntu_cis_24_l2``).
        requirement: Checklist requirement that could not be assessed.
        finding: Partial finding with error evidence or notes.
        evidence_dir: Optional path to evidence folder for operator reference.

    Returns:
        Markdown string shown to the operator during HITL pause.
    """
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
    """Wrap interrupt prompt with a resume marker for the chat API.

    Embeds ``[AUDIT_HITL:<thread_id>]`` so the next user message can be
    correlated with the paused LangGraph thread.

    Args:
        prompt: Body from :func:`build_hitl_prompt`.
        thread_id: LangGraph checkpoint thread id.

    Returns:
        Markdown assistant message with marker and resume instructions.
    """
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_HITL:{thread_id}]\n"
        f"_Paused for human decision. Your next message resumes this audit._\n"
    )


def _default_recommendation(finding: Finding, requirement: Requirement) -> str:
    """Generate bullet remediation hints from finding text and requirement metadata.

    Inspects evidence/notes for SSH, MCP, timeout, and permission keywords
    and appends the checklist ``how_to_verify`` step when present.

    Args:
        finding: Partial finding with evidence or error notes.
        requirement: Source checklist requirement.

    Returns:
        Markdown bullet list of suggested next steps for the operator.
    """
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
    """Extract display text from a LangGraph Interrupt value.

    Args:
        value: Interrupt payload (dict with ``prompt``/``message``, or str).

    Returns:
        Human-readable prompt string for chat display.
    """
    if isinstance(value, dict):
        return str(value.get("prompt") or value.get("message") or value)
    return str(value)

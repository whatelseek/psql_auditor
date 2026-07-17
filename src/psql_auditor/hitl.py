"""Human-in-the-loop helpers for failed requirement assessments.

When a requirement cannot be audited, the graph interrupts and asks the
operator to **skip** or **try again**. Open WebUI resumes via the next chat
message (same pattern as LangGraph interrupt + Command(resume=…)).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from psql_auditor.checklist import Requirement
from psql_auditor.state import Finding

HitlAction = Literal["skip", "retry", "skip_all", "retry_all", "unknown"]

# Visible marker embedded in assistant replies so the next chat turn can resume.
HITL_MARKER_RE = re.compile(
    r"\[AUDIT_HITL:(?P<thread>[A-Za-z0-9._:-]+)\]",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class HitlDecision:
    """Parsed operator decision for a paused requirement."""

    action: HitlAction
    raw: str


def extract_hitl_thread_id(messages: list[Any]) -> str | None:
    """Find ``[AUDIT_HITL:<thread>]`` in recent assistant messages."""
    for msg in reversed(messages):
        role = getattr(msg, "role", None)
        content = getattr(msg, "content", None)
        if isinstance(msg, dict):
            role = msg.get("role")
            content = msg.get("content")
        if role not in ("assistant", "system") or not content:
            continue
        match = HITL_MARKER_RE.search(str(content))
        if match:
            return match.group("thread")
    return None


def parse_hitl_decision(text: Any) -> HitlDecision:
    """Parse skip / retry (and all variants) from free-text user reply."""
    if isinstance(text, dict):
        action = str(text.get("action") or text.get("decision") or "").strip().lower()
        raw = str(text.get("text") or text.get("raw") or action)
        if action in ("skip", "retry", "skip_all", "retry_all"):
            return HitlDecision(action=action, raw=raw)  # type: ignore[arg-type]
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
    normalized = re.sub(r"\s+", " ", raw.lower())

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

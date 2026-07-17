"""Human-in-the-loop helpers for failed requirement assessments.

When a requirement cannot be audited, the graph interrupts and asks the
operator to **skip** or **try again**. Open WebUI resumes via the next chat
message (same pattern as LangGraph interrupt + Command(resume=…)).

Operator-facing HITL text follows the selected response language (Russian
by default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from psql_auditor.checklist import Requirement
from psql_auditor.language import ResponseLanguage, ui
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
    """Parse skip / retry (EN + RU variants) from free-text user reply."""
    if isinstance(text, dict):
        action = str(text.get("action") or text.get("decision") or "").strip().lower()
        raw = str(text.get("text") or text.get("raw") or action)
        if action in ("skip", "retry", "skip_all", "retry_all"):
            return HitlDecision(action=action, raw=raw)  # type: ignore[arg-type]
        text = raw

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

    if (
        re.search(r"\bskip\s+all\b", normalized)
        or re.search(r"пропустить\s+все", normalized)
        or normalized in {"sa", "skipall"}
    ):
        return HitlDecision(action="skip_all", raw=raw)
    if (
        re.search(r"\b(retry|try)\s+all\b", normalized)
        or re.search(r"повторить\s+все", normalized)
        or normalized in {"ra", "retryall"}
    ):
        return HitlDecision(action="retry_all", raw=raw)
    if re.search(
        r"\b(skip|skipped|ignore|pass)\b|пропустить|пропуск|пропусти",
        normalized,
    ) or normalized in {"s", "no", "n"}:
        return HitlDecision(action="skip", raw=raw)
    if re.search(
        r"\b(retry|try again|try|recheck|rerun|again)\b|повторить|повтор|"
        r"ещё раз|еще раз|заново",
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
    language: ResponseLanguage | None = None,
) -> str:
    """Human-readable interrupt prompt for one failed requirement."""
    lang = language or ResponseLanguage(code="ru", name="Russian")
    why = (
        finding.evidence
        or finding.notes
        or ui(lang, "no_evidence")
    ).strip()
    recommendation = (
        finding.remediation or _default_recommendation(finding, requirement, lang)
    ).strip()
    lines = [
        ui(lang, "hitl_title", req_id=requirement.id),
        "",
        ui(lang, "hitl_framework", framework_id=framework_id),
        ui(lang, "hitl_requirement", title=requirement.title),
        ui(
            lang,
            "hitl_category",
            category=requirement.category or "—",
            severity=requirement.severity or "—",
        ),
        "",
        ui(lang, "hitl_why"),
        why,
        "",
        ui(lang, "hitl_pass"),
        requirement.pass_criteria or "—",
        "",
        ui(lang, "hitl_how"),
        requirement.how_to_verify or "—",
        "",
        ui(lang, "hitl_reco"),
        recommendation,
    ]
    if evidence_dir:
        lines.extend(["", ui(lang, "hitl_evidence", evidence_dir=evidence_dir)])
    lines.extend(
        [
            "",
            ui(lang, "hitl_what"),
            ui(lang, "hitl_reply"),
            ui(lang, "hitl_opt_skip"),
            ui(lang, "hitl_opt_retry"),
            ui(lang, "hitl_opt_skip_all"),
            ui(lang, "hitl_opt_retry_all"),
        ]
    )
    return "\n".join(lines)


def format_hitl_assistant_message(
    prompt: str,
    thread_id: str,
    *,
    language: ResponseLanguage | None = None,
) -> str:
    """Wrap interrupt prompt with a resume marker for the chat API."""
    lang = language or ResponseLanguage(code="ru", name="Russian")
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_HITL:{thread_id}]\n"
        f"{ui(lang, 'hitl_paused')}\n"
    )


def _default_recommendation(
    finding: Finding,
    requirement: Requirement,
    lang: ResponseLanguage,
) -> str:
    blob = f"{finding.evidence} {finding.notes}".lower()
    tips: list[str] = []
    if lang.code == "ru":
        if "ssh" in blob or "not configured" in blob:
            tips.append(
                "Проверьте `SSH_HOST` / учётные данные и доступность хоста из агента."
            )
        if "mcp" in blob or "postgres" in blob or "connection" in blob:
            tips.append(
                "Проверьте `PG_*` / `DATABASE_URL` и подключение antonorlov/mcp-postgres-server."
            )
        if "timeout" in blob:
            tips.append("Увеличьте таймауты или снизьте нагрузку на цель, затем повторите.")
        if "permission" in blob or "denied" in blob:
            tips.append(
                "Выдайте пользователю аудита права на чтение нужных файлов/представлений."
            )
        if not tips:
            tips.append(
                "Исправьте проблему доступа/конфигурации выше и ответьте **повторить**; "
                "или **пропустить**, если проверка вне объёма."
            )
        if requirement.how_to_verify:
            tips.append(f"Ручная проверка: {requirement.how_to_verify}")
    else:
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

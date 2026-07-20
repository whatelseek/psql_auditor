"""Classify chat intents: full framework audit vs ad-hoc command execution.

Open WebUI sends every turn to ``/v1/chat/completions``. Without a gate, the
graph always starts a checklist audit. This module detects when the operator
asked to **run commands** (SSH / SQL / playbook tools) instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

IntentKind = Literal["audit", "adhoc"]

# Strong "run a command" signals (EN + RU).
_ADHOC_PATTERNS = (
    re.compile(
        r"\b(run|execute|exec)\s+(this\s+)?(command|cmd|ssh|sql|query|check)\b",
        re.I,
    ),
    re.compile(r"\b(run|execute)\s+[`'\"]", re.I),
    re.compile(r"\bjust\s+run\b", re.I),
    re.compile(r"\badihoc\b|\bad-hoc\b|\bone-?shot\b", re.I),
    re.compile(r"\brun\s+req[-\s]?\d+\b", re.I),
    re.compile(r"\b(execute|run)\s+(the\s+)?(playbook|commands?\s+for)\b", re.I),
    re.compile(
        r"\b(ssh_run|ssh_read_file|mcp_query)\b",
        re.I,
    ),
    re.compile(
        r"(выполн(и|ить)|запуст(и|ить))\s+(эту\s+)?(команд|проверк|запрос)",
        re.I,
    ),
    re.compile(r"\bвыполни\s+команд", re.I),
    re.compile(r"\bпроверь\s+(через|командой|sql|ssh)\b", re.I),
)

# Shell / SQL payload hints inside the message.
_COMMAND_PAYLOAD = (
    re.compile(r"`[^`]{2,}`"),
    re.compile(r"\b(SELECT|SHOW)\s+\w+", re.I),
    re.compile(
        r"\b(cat|grep|sshd|systemctl|ufw|chmod|ls\s+-|ss\s+-|netstat|powershell)\b",
        re.I,
    ),
)

# Prefer full audit when these dominate.
_AUDIT_PATTERNS = (
    re.compile(r"\b(full\s+)?(cis\s+)?audit\b", re.I),
    re.compile(r"\bstart\s+(a\s+)?(full\s+)?(postgres|postgresql|ubuntu|windows)?\b", re.I),
    re.compile(r"\b(framework|checklist)\b", re.I),
    re.compile(r"\bпровед(и|ить)\s+аудит\b", re.I),
    re.compile(r"\bзапусти\s+аудит\b", re.I),
)

_REQ_ID = re.compile(r"\bREQ[-\s]?(\d{1,4})\b", re.I)


def extract_req_ids(text: str) -> list[str]:
    """Return normalized ``REQ-NNN`` ids mentioned in ``text`` (order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    for match in _REQ_ID.finditer(text or ""):
        req_id = f"REQ-{int(match.group(1)):03d}"
        if req_id not in seen:
            seen.add(req_id)
            out.append(req_id)
    return out


def classify_intent(text: str, *, agents_dir: Path | None = None) -> IntentKind:
    """Decide whether ``text`` should start a checklist audit or ad-hoc commands.

    Defaults to ``audit`` so existing Open WebUI flows stay unchanged unless the
    operator clearly asks to run commands.

    Args:
        text: Latest user message.
        agents_dir: Unused today; reserved for framework-aware scoring.

    Returns:
        ``\"adhoc\"`` or ``\"audit\"``.
    """
    del agents_dir  # reserved
    raw = (text or "").strip()
    if not raw:
        return "audit"

    adhoc_hits = sum(1 for pat in _ADHOC_PATTERNS if pat.search(raw))
    payload_hits = sum(1 for pat in _COMMAND_PAYLOAD if pat.search(raw))
    audit_hits = sum(1 for pat in _AUDIT_PATTERNS if pat.search(raw))
    req_ids = extract_req_ids(raw)

    # Explicit "run REQ-…" / playbook commands without "audit" → adhoc.
    if req_ids and adhoc_hits and not audit_hits:
        return "adhoc"
    if req_ids and re.search(r"\b(run|execute|выполн|запуст)\b", raw, re.I) and not audit_hits:
        return "adhoc"

    # Clear command-runner phrasing.
    if adhoc_hits >= 1 and audit_hits == 0:
        return "adhoc"
    if adhoc_hits >= 1 and payload_hits >= 1 and audit_hits <= adhoc_hits:
        return "adhoc"

    # Bare payload ("run: SELECT …" / fenced shell) with a run verb.
    if payload_hits >= 1 and re.search(r"\b(run|execute|выполн|запуст|check)\b", raw, re.I):
        if audit_hits == 0:
            return "adhoc"

    return "audit"

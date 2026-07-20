"""Classify chat intents: audit, ad-hoc, post-audit revise, report update."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

IntentKind = Literal["audit", "adhoc", "revise_req", "update_report"]

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

_COMMAND_PAYLOAD = (
    re.compile(r"`[^`]{2,}`"),
    re.compile(r"\b(SELECT|SHOW)\s+\w+", re.I),
    re.compile(
        r"\b(cat|grep|sshd|systemctl|ufw|chmod|ls\s+-|ss\s+-|netstat|powershell)\b",
        re.I,
    ),
)

_AUDIT_PATTERNS = (
    re.compile(r"\b(full\s+)?(cis\s+)?audit\b", re.I),
    re.compile(r"\bstart\s+(a\s+)?(full\s+)?(postgres|postgresql|ubuntu|windows)?\b", re.I),
    re.compile(r"\b(framework|checklist)\b", re.I),
    re.compile(r"\bпровед(и|ить)\s+аудит\b", re.I),
    re.compile(r"\bзапусти\s+аудит\b", re.I),
)

_UPDATE_REPORT = (
    re.compile(r"\bupdate\s+(the\s+)?report\b", re.I),
    re.compile(r"\bregenerate\s+(the\s+)?report\b", re.I),
    re.compile(r"\brebuild\s+(the\s+)?report\b", re.I),
    re.compile(r"\brefresh\s+(the\s+)?report\b", re.I),
    re.compile(r"\bupdate\s+report\s+from\s+(new\s+)?evidence\b", re.I),
    re.compile(r"\bобнов(и|ить)\s+отч[её]т\b", re.I),
    re.compile(r"\bпересобер(и|ить)\s+отч[её]т\b", re.I),
    re.compile(r"\bобнов(и|ить)\s+отч[её]т\s+по\s+новым\s+данным\b", re.I),
)

_REVISE_REQ = (
    re.compile(r"\brevise\s+req", re.I),
    re.compile(r"\bre-?check\s+req", re.I),
    re.compile(r"\breassess\s+req", re.I),
    re.compile(r"\bre-?audit\s+req", re.I),
    re.compile(r"\brevise\s+REQ", re.I),
    re.compile(r"\bcheck\s+REQ[-\s]?\d+\s+again\b", re.I),
    re.compile(r"\brun\s+another\s+(command|check).*\bREQ", re.I | re.S),
    re.compile(r"\badditional\s+(check|command|evidence).*\bREQ", re.I | re.S),
    re.compile(r"\bперепровер(ь|ить)\s+REQ", re.I),
    re.compile(r"\bпересмотр(и|еть)\s+REQ", re.I),
    re.compile(r"\bдополнительн\w*\s+(провер|команд).*\bREQ", re.I | re.S),
    re.compile(r"\bпроверь\s+REQ[-\s]?\d+\s+(ещё|еще)\s+раз\b", re.I),
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
    """Classify the latest operator message into a chat intent.

    Defaults to ``audit`` so existing Open WebUI flows stay unchanged unless the
    operator clearly asks for commands, REQ revision, or report rebuild.
    """
    del agents_dir  # reserved
    raw = (text or "").strip()
    if not raw:
        return "audit"

    if any(pat.search(raw) for pat in _UPDATE_REPORT):
        return "update_report"

    req_ids = extract_req_ids(raw)
    if req_ids and any(pat.search(raw) for pat in _REVISE_REQ):
        return "revise_req"

    adhoc_hits = sum(1 for pat in _ADHOC_PATTERNS if pat.search(raw))
    payload_hits = sum(1 for pat in _COMMAND_PAYLOAD if pat.search(raw))
    audit_hits = sum(1 for pat in _AUDIT_PATTERNS if pat.search(raw))

    # REQ-targeted command / recheck after an audit → revise (same evidence folder).
    if req_ids and audit_hits == 0:
        if adhoc_hits or re.search(
            r"\b(run|execute|check|verify|выполн|запуст|проверь|перепроверь)\b",
            raw,
            re.I,
        ):
            return "revise_req"

    if req_ids and adhoc_hits and not audit_hits:
        return "revise_req"

    if adhoc_hits >= 1 and audit_hits == 0:
        return "adhoc"
    if adhoc_hits >= 1 and payload_hits >= 1 and audit_hits <= adhoc_hits:
        return "adhoc"

    if payload_hits >= 1 and re.search(r"\b(run|execute|выполн|запуст|check)\b", raw, re.I):
        if audit_hits == 0:
            return "adhoc"

    return "audit"

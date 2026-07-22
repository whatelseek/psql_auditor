"""Deterministic chat-intent classification for the Open WebUI entry point.

Runs on every incoming operator message **before** the LangGraph audit graph is
invoked. The API layer calls :func:`classify_intent` to decide which handler
path to take: a full checklist audit, ad-hoc command execution, REQ re-evaluation,
finding cell refill, report rebuild, or session listing.

This module is intentionally regex-based (no LLM) so routing is fast, reproducible,
and safe for production. English and Russian operator phrases are supported.
Default intent is ``audit`` so existing "start an audit" flows remain unchanged
unless the message clearly signals another mode.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

IntentKind = Literal[
    "audit",
    "adhoc",
    "revise_req",
    "refill_finding",
    "update_report",
    "list_sessions",
    "list_results",
    "list_status",
    "list_host",
]

# Deterministic playbook / freeform command path (not REQ evidence-gather revise).
_PLAYBOOK_ADHOC = (
    re.compile(r"\b(execute|run)\s+(the\s+)?(playbook|commands?\s+for)\b", re.I),
    re.compile(r"\bplaybook\s+commands?\b", re.I),
)

# Strong "run a command" signals (EN + RU). Keep narrow — bare verbs like
# ``list`` / ``try`` alone must not steal full-audit chats.
_ADHOC_PATTERNS = (
    re.compile(
        r"\b(run|execute|exec)\s+(this\s+)?(command|cmd|ssh|sql|query|check)\b",
        re.I,
    ),
    re.compile(r"\b(run|execute)\s+[`'\"]", re.I),
    re.compile(r"\bjust\s+run\b", re.I),
    re.compile(r"\badihoc\b|\bad-hoc\b|\bone-?shot\b", re.I),
    re.compile(r"\brun\s+req[-\s]?\d+\b", re.I),
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
        r"\b(cat|grep|sshd|systemctl|ufw|chmod|ls\s+-|ss\s+-|netstat|powershell|ps\s+aux|ps\s+-)\b",
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

# Warehouse REQ cells for a finished/running session (must win over list_sessions).
_LIST_RESULTS = (
    re.compile(r"\blist[- ]?results\b", re.I),
    re.compile(r"\bshow\s+(me\s+)?(warehouse\s+)?results\b", re.I),
    re.compile(r"\bwarehouse\s+results\b", re.I),
    re.compile(r"\bрезультаты\s+(сессии|аудита|склада)\b", re.I),
    re.compile(r"\bсписок\s+результатов\b", re.I),
    re.compile(r"\bпокажи\s+результаты\b", re.I),
)

# Host progress table (N/M ready) — prefer over list_sessions.
_LIST_STATUS = (
    re.compile(r"\blist[- ]?status\b", re.I),
    re.compile(r"\bhost\s+status\b", re.I),
    re.compile(r"\bстатус\s+(хостов|сессии|аудита)\b", re.I),
    re.compile(r"\bсписок\s+статус\w*\b", re.I),
)

# Per-host framework assessment dump.
_LIST_HOST = (
    re.compile(r"\blist[- ]?host\b", re.I),
    re.compile(r"\bhost\s+results?\b", re.I),
    re.compile(r"\bрезультаты\s+хоста\b", re.I),
    re.compile(r"\bпокажи\s+хост\b", re.I),
)

# Which warehouse sessions exist / need continue (Postgres tracker).
_LIST_SESSIONS = (
    re.compile(r"\bwhich\s+sessions?\b", re.I),
    re.compile(r"\blist\s+(audit\s+)?sessions?\b", re.I),
    re.compile(r"\bsessions?\s+need\s+continue\b", re.I),
    re.compile(r"\binterrupted\s+sessions?\b", re.I),
    re.compile(r"\bshow\s+(me\s+)?(audit\s+)?sessions?\b", re.I),
    re.compile(r"\bкакие\s+сессии\b", re.I),
    re.compile(r"\bсписок\s+сессий\b", re.I),
    re.compile(r"\bсессии\s+(для\s+продолж|прерван)", re.I),
    re.compile(r"\bпрерванн\w*\s+сессии\b", re.I),
    re.compile(r"\bнужно\s+продолжить\b", re.I),
)

# Prepare / rewrite observation + recommendation from already collected evidence.
_REFILL_FINDING = (
    re.compile(r"\bprepare\s+(a\s+)?new\s+(observation|recommendation)\b", re.I),
    re.compile(r"\b(update|rewrite|refresh)\s+(the\s+)?(observation|recommendation)s?\b", re.I),
    re.compile(r"\bnew\s+(observation|recommendation)s?\b", re.I),
    re.compile(r"\brefill\s+(the\s+)?(finding|cells?|observation)\b", re.I),
    re.compile(
        r"\b(observation|recommendation)s?\s+(and|&)\s+(observation|recommendation)s?\b",
        re.I,
    ),
    re.compile(
        r"\b(update|prepare|write)\s+(status|observation|recommendation)\b",
        re.I,
    ),
    re.compile(r"\bподготов(ь|ить)\s+(нов(ое|ые)\s+)?наблюден", re.I),
    re.compile(r"\bобнов(и|ить)\s+(наблюден|рекомендац)", re.I),
    re.compile(r"\bнов(ое|ые)\s+(наблюден|рекомендац)", re.I),
    re.compile(r"\bперепис(и|ать)\s+(наблюден|рекомендац)", re.I),
)

# REQ re-evaluation / extra checks into the same evidence folder.
_REVISE_REQ = (
    re.compile(r"\brevise\s+req", re.I),
    re.compile(r"\bevaluate\s+req", re.I),
    re.compile(r"\bre-?evaluate\s+req", re.I),
    re.compile(r"\bre-?check\s+req", re.I),
    re.compile(r"\breassess\s+req", re.I),
    re.compile(r"\bre-?audit\s+req", re.I),
    re.compile(r"\brevise\s+REQ", re.I),
    re.compile(r"\bevaluate\s+REQ", re.I),
    re.compile(r"\bcheck\s+REQ[-\s]?\d+\s+again\b", re.I),
    re.compile(r"\brun\s+another\s+(command|check).*\bREQ", re.I | re.S),
    re.compile(r"\badditional\s+(check|command|evidence).*\bREQ", re.I | re.S),
    re.compile(r"\bgather\s+(evidence|data|info).*\bREQ", re.I | re.S),
    re.compile(r"\bcollect\s+(evidence|data|info).*\bREQ", re.I | re.S),
    re.compile(r"\bперепровер(ь|ить)\s+REQ", re.I),
    re.compile(r"\bпересмотр(и|еть)\s+REQ", re.I),
    re.compile(r"\bоцен(и|ить)\s+REQ", re.I),
    re.compile(r"\bдополнительн\w*\s+(провер|команд).*\bREQ", re.I | re.S),
    re.compile(r"\b(собери|собрать)\s+(доказательств|улик|evidence).*\bREQ", re.I | re.S),
    re.compile(r"\bпроверь\s+REQ[-\s]?\d+\s+(ещё|еще)\s+раз\b", re.I),
)

# Full revise = gather tools + immediately rewrite observation/recommendation.
_FULL_REVISE = (
    re.compile(r"\brevise\s+req", re.I),
    re.compile(r"\breassess\s+req", re.I),
    re.compile(r"\bre-?audit\s+req", re.I),
    re.compile(r"\bпересмотр(и|еть)\s+REQ", re.I),
)

_REQ_ID = re.compile(r"\bREQ[-\s]?(\d{1,4})\b", re.I)


def extract_req_ids(text: str) -> list[str]:
    """Extract and normalize checklist requirement ids from free-form text.

    Scans ``text`` for patterns like ``REQ-1``, ``REQ 42``, or ``req-003`` and
    returns canonical ``REQ-NNN`` strings (three-digit zero padding). Duplicates
    are removed while preserving first-seen order.

    Args:
        text: Operator message or command payload. ``None`` is treated as empty.

    Returns:
        Ordered list of unique requirement ids, e.g. ``["REQ-001", "REQ-042"]``.
    """
    seen: set[str] = set()
    out: list[str] = []
    for match in _REQ_ID.finditer(text or ""):
        req_id = f"REQ-{int(match.group(1)):03d}"
        if req_id not in seen:
            seen.add(req_id)
            out.append(req_id)
    return out


def wants_full_revise(text: str) -> bool:
    """Detect a "full revise" request that combines evidence and cell rewrite.

    A full revise means the operator wants the agent to gather additional evidence
    for one or more REQs **and** immediately regenerate observation/recommendation
    cells in a single step (as opposed to evidence-only revision).

    Args:
        text: Operator message to inspect.

    Returns:
        ``True`` when strong full-revise phrases (e.g. "revise req", "reassess req")
        appear in ``text``; otherwise ``False``.
    """
    raw = text or ""
    return any(pat.search(raw) for pat in _FULL_REVISE)


def classify_intent(text: str, *, agents_dir: Path | None = None) -> IntentKind:
    """Classify the latest operator message into a chat intent.

    Evaluates regex pattern groups in priority order: session listing, finding
    refill, report update, playbook ad-hoc, REQ revision, general ad-hoc commands,
    and finally full audit. REQ ids in the message can steer borderline cases
    toward ``revise_req`` when the operator references a requirement without
    starting a new audit.

    Defaults to ``audit`` so existing Open WebUI flows stay unchanged unless the
    operator clearly asks for commands, REQ revision, refill, or report rebuild.

    Args:
        text: Raw operator message from chat.
        agents_dir: Reserved for future framework-aware routing; currently ignored.

    Returns:
        One of the :data:`IntentKind` literals describing the handler to invoke.
    """
    del agents_dir  # reserved
    raw = (text or "").strip()
    if not raw:
        return "audit"

    # Prefer REQ warehouse dump over session listing when both match.
    if any(pat.search(raw) for pat in _LIST_RESULTS):
        return "list_results"

    if any(pat.search(raw) for pat in _LIST_STATUS):
        return "list_status"

    if any(pat.search(raw) for pat in _LIST_HOST):
        return "list_host"

    if any(pat.search(raw) for pat in _LIST_SESSIONS):
        return "list_sessions"

    # Prefer cell refill over report rebuild when both phrases appear.
    if any(pat.search(raw) for pat in _REFILL_FINDING):
        return "refill_finding"

    if any(pat.search(raw) for pat in _UPDATE_REPORT):
        return "update_report"

    # Deterministic playbook path (docs: ad-hoc), even when a REQ id is present.
    if any(pat.search(raw) for pat in _PLAYBOOK_ADHOC):
        return "adhoc"

    req_ids = extract_req_ids(raw)
    if req_ids and any(pat.search(raw) for pat in _REVISE_REQ):
        return "revise_req"

    adhoc_hits = sum(1 for pat in _ADHOC_PATTERNS if pat.search(raw))
    payload_hits = sum(1 for pat in _COMMAND_PAYLOAD if pat.search(raw))
    audit_hits = sum(1 for pat in _AUDIT_PATTERNS if pat.search(raw))

    # REQ-targeted command / recheck after an audit → revise (same evidence folder).
    if req_ids and audit_hits == 0:
        if adhoc_hits or re.search(
            r"\b(run|execute|check|verify|evaluate|list|read|try|"
            r"gather|collect|выполн|запуст|проверь|перепроверь|оцен|"
            r"список|прочит|собери|собрать)\b",
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

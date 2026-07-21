"""Pre-audit intake: client, CMDB, access, audit type (chat interrupts).

This module drives the **four-step questionnaire** that runs before a checklist
audit when intake is enabled. It collects client name, CMDB availability,
server access, and audit domain (IT / Cybersecurity / both), then maps answers
to framework selection and inventory probes.

Pipeline role:
    The graph interrupts with ``[AUDIT_INTAKE:<thread>]`` markers between
    steps. Parsing helpers support both regex (fast path) and LLM JSON
    interpretation for ambiguous replies.

Key entry points:
    :func:`prompts_for_language` — localized step prompts (EN/RU).
    :func:`format_intake_assistant_message` — embed intake marker in chat.
    :func:`resolve_client_name` / :func:`resolve_yes_no` / :func:`resolve_audit_type` — structured answers.
    :func:`frameworks_for_audit_type` — map domain choice to framework ids.
    :func:`summarize_cmdb_capabilities` / :func:`summarize_access_probe` — probe result Markdown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

# ``cis`` retained as alias of ``cybersecurity`` for backward compatibility.
AuditType = Literal["cis", "cybersecurity", "it", "both"]
YesNo = Literal["yes", "no", "unknown"]

INTAKE_MARKER_RE = re.compile(
    r"\[AUDIT_INTAKE:(?P<thread>[A-Za-z0-9._:-]+)\]",
    re.IGNORECASE,
)

_YES = re.compile(
    r"^\s*(y|yes|да|есть|имеется|true|1)\b",
    re.I,
)
_NO = re.compile(
    r"^\s*(n|no|нет|нету|false|0)\b",
    re.I,
)


@dataclass(frozen=True, slots=True)
class IntakePrompts:
    """Localized Markdown prompts for each intake questionnaire step.

    Attributes:
        client: Step 1 — client / organization name.
        cmdb: Step 2 — CMDB / NetBox availability (yes/no).
        access: Step 3 — SSH/service access for probing.
        audit_type: Step 4 — IT vs Cybersecurity vs both.
    """

    client: str
    cmdb: str
    access: str
    audit_type: str


def client_slug(name: str) -> str:
    """Derive a filesystem-safe slug from a client display name.

    Replaces non-alphanumeric characters with underscores, truncates to 64
    chars, and lowercases. Used for evidence and inventory folder names.

    Args:
        name: Raw client or organization name from intake.

    Returns:
        Safe slug string; defaults to ``"client"`` when empty after cleaning.
    """
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", (name or "").strip()).strip("_")
    return (slug[:64] or "client").lower()


def parse_yes_no(text: str) -> YesNo:
    """Parse yes/no intent from operator text using regex heuristics.

    Supports English and Russian affirmatives/negatives at line start and
    as embedded words when the reply is short.

    Args:
        text: Operator reply to a yes/no intake question.

    Returns:
        ``"yes"``, ``"no"``, or ``"unknown"`` when ambiguous or empty.
    """
    raw = (text or "").strip()
    if not raw:
        return "unknown"
    if _YES.search(raw):
        return "yes"
    if _NO.search(raw):
        return "no"
    # Soft: contains yes/no words
    lower = raw.lower()
    if re.search(r"\b(yes|да|есть)\b", lower):
        return "yes"
    if re.search(r"\b(no|нет)\b", lower):
        return "no"
    return "unknown"


def resolve_yes_no(text: str, llm_payload: dict[str, Any] | None = None) -> YesNo:
    """Resolve yes/no from LLM JSON payload or regex fallback.

    Args:
        text: Raw operator reply.
        llm_payload: Optional dict from intake interpret model with ``answer`` key.

    Returns:
        ``"yes"``, ``"no"``, or ``"unknown"``.
    """
    if isinstance(llm_payload, dict):
        ans = str(llm_payload.get("answer") or "").strip().lower()
        if ans in {"yes", "y", "true", "1", "да"}:
            return "yes"
        if ans in {"no", "n", "false", "0", "нет", "nay", "nope"}:
            return "no"
        if ans == "unknown":
            # Still try regex in case the model hedged on a clear reply
            regex = parse_yes_no(text)
            return regex if regex != "unknown" else "unknown"
    return parse_yes_no(text)


def resolve_client_name(
    text: str, llm_payload: dict[str, Any] | None = None
) -> str:
    """Resolve client name from LLM JSON or regex parser.

    Args:
        text: Raw operator reply.
        llm_payload: Optional dict with ``client_name`` key.

    Returns:
        Trimmed client name (max 120 chars), or empty string.
    """
    if isinstance(llm_payload, dict):
        name = str(llm_payload.get("client_name") or "").strip()
        if name:
            return name[:120]
    return parse_client_name(text)


def resolve_audit_type(
    text: str, llm_payload: dict[str, Any] | None = None
) -> AuditType | None:
    """Resolve audit domain from LLM JSON or regex parser.

    Normalizes ``cis`` / ``cyber`` aliases to ``cybersecurity``.

    Args:
        text: Raw operator reply.
        llm_payload: Optional dict with ``audit_type`` key.

    Returns:
        ``"it"``, ``"cybersecurity"``, ``"both"``, or ``None`` when unclear.
    """
    if isinstance(llm_payload, dict) and "audit_type" in llm_payload:
        raw = llm_payload.get("audit_type")
        if raw is None or str(raw).strip().lower() in {"", "null", "none", "unknown"}:
            return parse_audit_type(text)
        at = str(raw).strip().lower()
        if at in {"cis", "cyber", "cybersecurity"}:
            return "cybersecurity"
        if at in {"it"}:
            return "it"
        if at in {"both"}:
            return "both"
    return parse_audit_type(text)


def parse_client_name(text: str) -> str:
    """Extract client name from free text, stripping common label prefixes.

    Removes leading patterns like "Client:", "клиент:", etc.

    Args:
        text: Operator reply to the client name intake step.

    Returns:
        Trimmed name (max 120 chars), or empty string.
    """
    raw = (text or "").strip()
    # Strip common prefixes
    raw = re.sub(
        r"^(client(\s+name)?|клиент|название)\s*[:=-]?\s*",
        "",
        raw,
        flags=re.I,
    ).strip()
    return raw[:120] if raw else ""


def parse_audit_type(text: str) -> AuditType | None:
    """Parse domain scope: IT / Cybersecurity / both (``cis`` → cybersecurity).

    Recognizes combined phrases (``both``, ``IT + CIS``), numbered menu replies,
    and Russian keywords.

    Args:
        text: Operator reply to the audit type intake step.

    Returns:
        ``"it"``, ``"cybersecurity"``, ``"both"``, or ``None`` when unclear.
    """
    lower = (text or "").strip().lower()
    if not lower:
        return None
    if re.search(
        r"\bboth\b|оба|"
        r"cis\s*\+\s*it|it\s*\+\s*cis|"
        r"cyber\s*\+\s*it|it\s*\+\s*cyber|"
        r"cybersecurity\s*\+\s*it|it\s*\+\s*cybersecurity",
        lower,
    ):
        return "both"
    cyber = bool(
        re.search(r"\bcis\b|cyber\s*security|cybersecurity|кибер", lower)
    )
    it_only = bool(
        re.search(r"\bit[\s_-]?audit\b|ит[\s_-]?аудит|inventory", lower)
        or re.search(r"\bit\b|ит", lower)
    )
    if cyber and it_only:
        return "both"
    if re.search(r"\bit[\s_-]?audit\b|ит[\s_-]?аудит|inventory", lower) and not cyber:
        return "it"
    if cyber:
        return "cybersecurity"
    if re.search(r"\bit\b|inventory|ит", lower):
        return "it"
    if lower in {"1", "cis", "cyber", "cybersecurity"}:
        return "cybersecurity"
    if lower in {"2", "it"}:
        return "it"
    if lower in {"3", "both"}:
        return "both"
    return None


def domains_for_audit_type(audit_type: AuditType | str) -> list[str]:
    """Map intake scope to framework ``domain`` values (``it`` / ``cybersecurity``).

    Args:
        audit_type: One of ``it``, ``cybersecurity``, ``cis``, or ``both``.

    Returns:
        List of domain strings used by framework routing (one or two elements).
    """
    at = (audit_type or "both").strip().lower()
    if at in {"it"}:
        return ["it"]
    if at in {"cis", "cybersecurity", "cyber"}:
        return ["cybersecurity"]
    return ["it", "cybersecurity"]


def prompts_for_language(code: str) -> IntakePrompts:
    """Return localized intake step prompts for a language code.

    Args:
        code: BCP-47 or ISO language code; Russian when starting with ``ru``.

    Returns:
        :class:`IntakePrompts` with Markdown for all four intake steps.
    """
    if (code or "en").startswith("ru"):
        return IntakePrompts(
            client=(
                "## Предварительный опрос (1/4)\n\n"
                "Укажите **название клиента** (организация / проект)."
            ),
            cmdb=(
                "## Предварительный опрос (2/4)\n\n"
                "Есть ли у клиента **CMDB / NetBox**?\n\n"
                "Ответьте **да** или **нет**."
            ),
            access=(
                "## Предварительный опрос (3/4)\n\n"
                "Есть ли у меня **доступ к серверам и сервисам** для проверки?\n\n"
                "Ответьте **да** или **нет**."
            ),
            audit_type=(
                "## Предварительный опрос (4/4)\n\n"
                "Какой **домен** аудита провести?\n\n"
                "1. **IT** — инвентаризация и базовые IT-контроли\n"
                "2. **Cybersecurity** — CIS / hardening (Postgres / Ubuntu / Windows)\n"
                "3. **both** — сначала IT, затем Cybersecurity\n\n"
                "Фреймворки на каждом хосте выбираются автоматически по ОС и ПО.\n\n"
                "Ответьте: `IT`, `Cybersecurity`, или `both`."
            ),
        )
    return IntakePrompts(
        client=(
            "## Pre-audit intake (1/4)\n\n"
            "What is the **client name** (organization / engagement)?"
        ),
        cmdb=(
            "## Pre-audit intake (2/4)\n\n"
            "Does the client have a **CMDB / NetBox**?\n\n"
            "Reply **yes** or **no**."
        ),
        access=(
            "## Pre-audit intake (3/4)\n\n"
            "Do I have **access to servers and services** to probe?\n\n"
            "Reply **yes** or **no**."
        ),
        audit_type=(
            "## Pre-audit intake (4/4)\n\n"
            "Which audit **domain** should I run?\n\n"
            "1. **IT** — inventory + baseline IT controls\n"
            "2. **Cybersecurity** — CIS / hardening (Postgres / Ubuntu / Windows)\n"
            "3. **both** — IT first, then Cybersecurity\n\n"
            "Frameworks on each host are selected automatically from OS and software.\n\n"
            "Reply: `IT`, `Cybersecurity`, or `both`."
        ),
    )


def format_intake_assistant_message(prompt: str, thread_id: str) -> str:
    """Wrap an intake step prompt with ``[AUDIT_INTAKE:<thread>]`` marker.

    Args:
        prompt: Step question Markdown from :func:`prompts_for_language`.
        thread_id: LangGraph thread id for resume correlation.

    Returns:
        Assistant message with marker and continuation hint.
    """
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_INTAKE:{thread_id}]\n"
        f"_Paused for intake. Your next message continues this questionnaire._\n"
    )


def extract_intake_thread_id(messages: list[Any]) -> str | None:
    """Find intake thread only when it is the newest pause marker.

    Delegates to :func:`~auditor.hitl.resolve_pause_resume` and returns the
    thread id only when the active pause kind is ``intake``.

    Args:
        messages: Chat message history.

    Returns:
        Intake thread id string, or ``None`` when intake is not paused.
    """
    from auditor.hitl import resolve_pause_resume

    resolved = resolve_pause_resume(messages)
    if resolved and resolved[0] == "intake":
        return resolved[1]
    return None


def intake_interrupt_payload(*, step: str, prompt: str, **extra: Any) -> dict[str, Any]:
    """Build a LangGraph interrupt payload dict for an intake step.

    Args:
        step: Intake step identifier (e.g. ``client``, ``cmdb``).
        prompt: Display prompt shown to the operator.
        **extra: Additional fields merged into the payload.

    Returns:
        Dict with ``type``, ``step``, ``prompt``, and any extra keys.
    """
    return {"type": "intake", "step": step, "prompt": prompt, **extra}


def summarize_cmdb_capabilities(probe: dict[str, Any], *, language: str = "en") -> str:
    """Render NetBox/CMDB probe results as a Markdown table for the operator.

    Args:
        probe: Dict with ``reachable``, optional ``error``, and ``fields`` map.
        language: ``"en"`` or Russian when starting with ``ru``.

    Returns:
        Markdown section listing which CMDB fields are available.
    """
    reachable = bool(probe.get("reachable"))
    fields = probe.get("fields") or {}
    if language.startswith("ru"):
        lines = ["### Результат проверки NetBox", ""]
        if not reachable:
            lines.append(f"**Недоступен:** {probe.get('error') or 'нет ответа'}")
            return "\n".join(lines)
        lines.append("**Подключение:** успешно")
        lines.append("")
        lines.append("| Поле | Доступно |")
        lines.append("|---|---|")
        labels = {
            "hostname": "Hostname",
            "ip": "IP",
            "subnet": "Subnet",
            "owner": "Owner",
            "cpu": "CPU",
            "ram": "RAM",
            "storage": "HDD/SSD",
            "location": "Location",
            "access_port": "Access port",
            "access_method": "Access method",
        }
        for key, label in labels.items():
            info = fields.get(key) or {}
            ok = "да" if info.get("available") else "нет"
            note = info.get("note") or ""
            lines.append(f"| {label} | {ok}" + (f" — {note}" if note else "") + " |")
        return "\n".join(lines)

    lines = ["### NetBox probe result", ""]
    if not reachable:
        lines.append(f"**Unreachable:** {probe.get('error') or 'no response'}")
        return "\n".join(lines)
    lines.append("**Connection:** ok")
    lines.append("")
    lines.append("| Field | Available |")
    lines.append("|---|---|")
    labels = {
        "hostname": "Hostname",
        "ip": "IP",
        "subnet": "Subnet",
        "owner": "Owner",
        "cpu": "CPU",
        "ram": "RAM",
        "storage": "HDD/SSD",
        "location": "Location",
        "access_port": "Access port",
        "access_method": "Access method",
    }
    for key, label in labels.items():
        info = fields.get(key) or {}
        ok = "yes" if info.get("available") else "no"
        note = info.get("note") or ""
        lines.append(f"| {label} | {ok}" + (f" — {note}" if note else "") + " |")
    return "\n".join(lines)


def summarize_access_probe(probe: dict[str, Any], *, language: str = "en") -> str:
    """Render access probe results as a Markdown table for the operator.

    Args:
        probe: Dict with ``services`` list of ``name`` / ``status`` / ``detail``.
        language: ``"en"`` or Russian when starting with ``ru``.

    Returns:
        Markdown section summarizing per-service reachability.
    """
    services = probe.get("services") or []
    if language.startswith("ru"):
        lines = ["### Проверка доступа", ""]
        if not services:
            lines.append("Сервисы не проверялись.")
            return "\n".join(lines)
        lines.append("| Сервис | Статус | Детали |")
        lines.append("|---|---|---|")
        for svc in services:
            lines.append(
                f"| {svc.get('name')} | {svc.get('status')} | "
                f"{svc.get('detail') or '—'} |"
            )
        return "\n".join(lines)

    lines = ["### Access probe", ""]
    if not services:
        lines.append("No services were probed.")
        return "\n".join(lines)
    lines.append("| Service | Status | Detail |")
    lines.append("|---|---|---|")
    for svc in services:
        lines.append(
            f"| {svc.get('name')} | {svc.get('status')} | {svc.get('detail') or '—'} |"
        )
    return "\n".join(lines)


def frameworks_for_audit_type(
    audit_type: AuditType,
    *,
    user_request: str,
    agents_dir: Any,
) -> list[str]:
    """Resolve ordered framework ids from intake domain (NLP fallback without hosts).

    Prefer host-driven ``select_frameworks_for_host`` after discovery; this helper
    remains for intake-disabled / no-SSH fallbacks.
    """
    from auditor.frameworks import list_frameworks, route_frameworks

    domains = domains_for_audit_type(audit_type)
    if domains == ["it"]:
        return ["it_audit"]
    if domains == ["cybersecurity"]:
        ids = [fw.id for fw in route_frameworks(user_request, agents_dir)]
        ids = [i for i in ids if i != "it_audit"]
        if not ids:
            all_fw = list_frameworks(agents_dir)
            ids = [f.id for f in all_fw if f.id.endswith("_cis") or "cis" in f.id]
        return ids or ["postgres_cis"]
    # both: IT first, then cybersecurity frameworks
    cis_ids = frameworks_for_audit_type(
        "cybersecurity", user_request=user_request, agents_dir=agents_dir
    )
    return ["it_audit", *[i for i in cis_ids if i != "it_audit"]]

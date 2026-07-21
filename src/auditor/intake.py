"""Pre-audit intake: client, CMDB, access, audit type (chat interrupts)."""

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
    client: str
    cmdb: str
    access: str
    audit_type: str


def client_slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", (name or "").strip()).strip("_")
    return (slug[:64] or "client").lower()


def parse_yes_no(text: str) -> YesNo:
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
    """Prefer LLM JSON ``answer``, else regex ``parse_yes_no``."""
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
    """Prefer LLM JSON ``client_name``, else ``parse_client_name``."""
    if isinstance(llm_payload, dict):
        name = str(llm_payload.get("client_name") or "").strip()
        if name:
            return name[:120]
    return parse_client_name(text)


def resolve_audit_type(
    text: str, llm_payload: dict[str, Any] | None = None
) -> AuditType | None:
    """Prefer LLM JSON ``audit_type``, else ``parse_audit_type``."""
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
    """Parse domain scope: IT / Cybersecurity / both (``cis`` → cybersecurity)."""
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
    """Map intake scope to framework ``domain`` values (``it`` / ``cybersecurity``)."""
    at = (audit_type or "both").strip().lower()
    if at in {"it"}:
        return ["it"]
    if at in {"cis", "cybersecurity", "cyber"}:
        return ["cybersecurity"]
    return ["it", "cybersecurity"]


def prompts_for_language(code: str) -> IntakePrompts:
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
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_INTAKE:{thread_id}]\n"
        f"_Paused for intake. Your next message continues this questionnaire._\n"
    )


def extract_intake_thread_id(messages: list[Any]) -> str | None:
    """Find intake thread only when it is the newest pause marker."""
    from auditor.hitl import resolve_pause_resume

    resolved = resolve_pause_resume(messages)
    if resolved and resolved[0] == "intake":
        return resolved[1]
    return None


def intake_interrupt_payload(*, step: str, prompt: str, **extra: Any) -> dict[str, Any]:
    return {"type": "intake", "step": step, "prompt": prompt, **extra}


def summarize_cmdb_capabilities(probe: dict[str, Any], *, language: str = "en") -> str:
    """Markdown summary of what NetBox can provide for the operator."""
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

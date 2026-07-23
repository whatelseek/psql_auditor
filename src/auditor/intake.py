"""Pre-audit intake: client, CMDB, access, framework scope (chat interrupts).

This module drives the **four-step questionnaire** that runs before a checklist
audit when intake is enabled. It collects client name, CMDB availability,
server access, then a host→framework proposal the operator can trim.

Pipeline role:
    The graph interrupts with ``[AUDIT_INTAKE:<thread>]`` markers between
    steps. Step 1 is deterministic; steps 2–4 resolve from LLM JSON only
    (no regex fallback on the intake path).

Key entry points:
    :func:`prompts_for_language` — localized step prompts (EN/RU).
    :func:`format_intake_assistant_message` — embed intake marker in chat.
    :func:`resolve_client_name` — deterministic step 1 (no LLM).
    :func:`resolve_yes_no` / :func:`resolve_audit_type`
    / :func:`resolve_scope_decision` — LLM JSON only for steps 2–4.
    :func:`frameworks_for_audit_type` — map domain choice to framework ids
    (no-access fallback).
    :func:`summarize_cmdb_capabilities` / :func:`summarize_access_probe` — probe Markdown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

# ``cis`` retained as alias of ``cybersecurity`` for backward compatibility.
AuditType = Literal["cis", "cybersecurity", "it", "both"]
YesNo = Literal["yes", "no", "unknown"]


@dataclass(frozen=True, slots=True)
class IntakePrompts:
    """Localized Markdown prompts for each intake questionnaire step.

    Attributes:
        client: Step 1 — client / organization name.
        cmdb: Step 2 — CMDB / NetBox availability (yes/no).
        access: Step 3 — SSH/service access for probing.
        scope: Step 4 — confirm or exclude proposed host→framework jobs.
        audit_type: Fallback step 4 when no host plan (no access) — domain pick.
    """

    client: str
    cmdb: str
    access: str
    scope: str
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


_YES_ANSWERS = frozenset(
    {
        "yes",
        "y",
        "true",
        "1",
        "да",
        "ага",
        "угу",
        "ок",
        "ok",
        "okay",
        "yeah",
        "yep",
        "sure",
        "конечно",
        "есть",
        "имеется",
        "доступен",
        "доступно",
    }
)
_NO_ANSWERS = frozenset(
    {
        "no",
        "n",
        "false",
        "0",
        "нет",
        "неа",
        "не",
        "nay",
        "nope",
        "нету",
        "нет доступа",
    }
)


def _normalize_yes_no_token(value: str) -> YesNo:
    """Map a short label/token to yes/no/unknown (no free-form regex)."""
    token = str(value or "").strip().lower().strip(".,!;:")
    if not token:
        return "unknown"
    if token in _YES_ANSWERS:
        return "yes"
    if token in _NO_ANSWERS:
        return "no"
    return "unknown"


def resolve_yes_no(text: str, llm_payload: dict[str, Any] | None = None) -> YesNo:
    """Resolve availability intent from the intake LLM JSON only (steps 2–3).

    The interpret model decides yes/no/unknown. This helper only normalizes the
    model's ``answer`` label (including when it echoes slang like ``ага``).
    Raw operator text is not pattern-matched.

    Args:
        text: Raw operator reply (unused; kept for call-site compatibility).
        llm_payload: Dict from intake interpret model with ``answer`` key.

    Returns:
        ``"yes"``, ``"no"``, or ``"unknown"``.
    """
    del text
    if not isinstance(llm_payload, dict):
        return "unknown"
    return _normalize_yes_no_token(str(llm_payload.get("answer") or ""))


def intake_clarification_from_payload(
    llm_payload: dict[str, Any] | None,
) -> str:
    """Extract optional clarification text when the operator asked a question.

    The yes/no interpreter may return ``clarification`` (or ``help``) explaining
    the current intake step so the re-prompt is useful (e.g. reply «что это?»).

    Args:
        llm_payload: JSON from the intake interpret model.

    Returns:
        Trimmed clarification Markdown, or empty string.
    """
    if not isinstance(llm_payload, dict):
        return ""
    for key in ("clarification", "help", "explanation", "message"):
        text = str(llm_payload.get(key) or "").strip()
        if text:
            return text[:2000]
    return ""


def resolve_client_name(
    text: str, llm_payload: dict[str, Any] | None = None
) -> str:
    """Resolve client name deterministically (intake step 1 — no LLM).

    ``llm_payload`` is ignored; kept for call-site compatibility.

    Args:
        text: Raw operator reply.
        llm_payload: Unused (step 1 is regex/parser only).

    Returns:
        Trimmed client name (max 120 chars), or empty string.
    """
    del llm_payload
    return parse_client_name(text)


def resolve_audit_type(
    text: str, llm_payload: dict[str, Any] | None = None
) -> AuditType | None:
    """Resolve audit domain from LLM JSON only (intake step 4).

    No regex fallback. Normalizes ``cis`` / ``cyber`` aliases to ``cybersecurity``.

    Args:
        text: Raw operator reply (unused; kept for call-site compatibility).
        llm_payload: Dict with ``audit_type`` key from the intake interpret model.

    Returns:
        ``"it"``, ``"cybersecurity"``, ``"both"``, or ``None`` when unclear.
    """
    del text
    if not isinstance(llm_payload, dict) or "audit_type" not in llm_payload:
        return None
    raw = llm_payload.get("audit_type")
    if raw is None or str(raw).strip().lower() in {
        "",
        "null",
        "none",
        "unknown",
    }:
        return None
    at = str(raw).strip().lower()
    if at in {"cis", "cyber", "cybersecurity"}:
        return "cybersecurity"
    if at in {"it"}:
        return "it"
    if at in {"both"}:
        return "both"
    return None


def resolve_scope_decision(
    text: str,
    proposed_jobs: list[dict[str, Any]],
    llm_payload: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | None:
    """Resolve selected jobs from LLM JSON only (intake step 4).

    No regex fallback. Unclear / missing payload → ``None`` (re-prompt).

    Returns:
        Filtered job list, or ``None`` when the reply is unclear (re-prompt).
        Empty list means everything was excluded (caller should re-prompt).
    """
    del text
    if not isinstance(llm_payload, dict):
        return None
    action = str(llm_payload.get("action") or "").strip().lower()
    if action in {"confirm", "all", "run_all", "accept"}:
        return [dict(r) for r in proposed_jobs]
    if action in {"exclude", "trim"}:
        excl_fw = {
            str(x).strip()
            for x in (llm_payload.get("exclude_frameworks") or [])
            if str(x).strip()
        }
        excl_pairs: set[tuple[str, str]] = set()
        for pair in llm_payload.get("exclude_pairs") or []:
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                excl_pairs.add((str(pair[0]).lower(), str(pair[1]).lower()))
            elif isinstance(pair, str) and "/" in pair:
                h, f = pair.split("/", 1)
                excl_pairs.add((h.strip().lower(), f.strip().lower()))
        return apply_scope_exclusions(proposed_jobs, excl_fw, excl_pairs)
    return None


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
                "Опишите ситуацию своими словами "
                "(например: «NetBox есть в проде», «ведём учёт в Excel»)."
            ),
            access=(
                "## Предварительный опрос (3/4)\n\n"
                "Есть ли у меня **доступ к серверам и сервисам** для проверки?\n\n"
                "Опишите ситуацию своими словами "
                "(например: «SSH на .79», «ты можешь туда попасть», "
                "«пока только документы»).\n\n"
                "Если доступ есть, будет показана таблица досягаемости "
                "(сервис / IP / порт / статус / применимые фреймворки)."
            ),
            scope=(
                "## Предварительный опрос (4/4)\n\n"
                "Ниже — предложенный план **хост → фреймворки**.\n\n"
                "Ответьте **подтвердить** / **все**, чтобы запустить весь план, "
                "или опишите, что **исключить** (свободный текст ок), например:\n"
                "- `exclude ubuntu_cis_24_l2, postgres_cis`\n"
                "- `exclude it_audit`\n"
                "- `exclude 10.0.0.1/ubuntu_cis_24_l2`\n"
                "- «убери ubuntu на .78»\n"
            ),
            audit_type=(
                "## Предварительный опрос (4/4)\n\n"
                "Живой план хостов недоступен (нет доступа / нет хостов в inventory).\n\n"
                "Какой **домен** аудита провести?\n\n"
                "1. **IT** — инвентаризация и базовые IT-контроли\n"
                "2. **Cybersecurity** — CIS / hardening (Postgres / Ubuntu / Windows)\n"
                "3. **both** — сначала IT, затем Cybersecurity\n\n"
                "Можно ответить `IT`, `Cybersecurity`, `both` или своими словами."
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
            "Describe the situation in your own words "
            "(e.g. \"We use NetBox in prod\", \"We track assets in Excel only\")."
        ),
        access=(
            "## Pre-audit intake (3/4)\n\n"
            "Do I have **access to servers and services** to probe?\n\n"
            "Describe the situation in your own words "
            "(e.g. \"SSH on .79\", \"you can get in\", \"docs only for now\").\n\n"
            "If access is available, I will list host/service reachability "
            "(service / IP / port / status / applicable frameworks)."
        ),
        scope=(
            "## Pre-audit intake (4/4)\n\n"
            "Below is the proposed **host → frameworks** plan.\n\n"
            "Reply **confirm** / **all** / **run all** to accept the full plan, "
            "or say what to **exclude** (free-form OK), e.g.:\n"
            "- `exclude ubuntu_cis_24_l2, postgres_cis`\n"
            "- `exclude it_audit`\n"
            "- `exclude 10.0.0.1/ubuntu_cis_24_l2`\n"
            "- \"skip ubuntu on .78\"\n"
        ),
        audit_type=(
            "## Pre-audit intake (4/4)\n\n"
            "No live host plan is available (no access / no inventory hosts).\n\n"
            "Which audit **domain** should I run?\n\n"
            "1. **IT** — inventory + baseline IT controls\n"
            "2. **Cybersecurity** — CIS / hardening (Postgres / Ubuntu / Windows)\n"
            "3. **both** — IT first, then Cybersecurity\n\n"
            "Reply `IT`, `Cybersecurity`, `both`, or in your own words."
        ),
    )


def format_discovered_software_markdown(
    proposed_jobs: list[dict[str, Any]],
    *,
    language: str = "en",
) -> str:
    """Render prerun software inventory used to choose audit frameworks.

    Args:
        proposed_jobs: Host rows that may include ``binaries``, ``packages``,
            ``key_files``, ``os_pretty_name``.
        language: ``en`` or Russian when starting with ``ru``.

    Returns:
        Markdown sections per host, or empty-state text.
    """
    ru = (language or "en").startswith("ru")
    if not proposed_jobs:
        return (
            "_Нет данных о ПО для выбора фреймворков._"
            if ru
            else "_No software inventory for framework selection._"
        )
    title = (
        "### Установленное ПО / файлы (для выбора фреймворка)"
        if ru
        else "### Installed packages / files (for framework selection)"
    )
    lines = [title, ""]
    for row in proposed_jobs:
        host = str(row.get("ssh_host") or row.get("host_id") or "—")
        hn = str(row.get("hostname") or "").strip()
        head = f"**`{host}`**" + (f" ({hn})" if hn else "")
        lines.append(head)
        os_name = str(row.get("os_pretty_name") or row.get("os_id") or "").strip()
        if os_name:
            lines.append(f"- **OS:** {os_name}")
        bins = [str(x) for x in (row.get("binaries") or []) if str(x).strip()]
        pkgs = [str(x) for x in (row.get("packages") or []) if str(x).strip()]
        highlights = [
            str(x) for x in (row.get("highlight_packages") or []) if str(x).strip()
        ]
        files = [str(x) for x in (row.get("key_files") or []) if str(x).strip()]
        notes = str(row.get("software_notes") or "").strip()
        lines.append(
            "- **Binaries:** " + (", ".join(f"`{b}`" for b in bins) if bins else "—")
        )
        if highlights:
            lines.append(
                "- **Packages (LLM highlights for frameworks):** "
                + ", ".join(f"`{p}`" for p in highlights)
            )
        if pkgs:
            if len(pkgs) <= 60:
                lines.append(
                    "- **Packages (full):** " + ", ".join(f"`{p}`" for p in pkgs)
                )
            else:
                preview = ", ".join(f"`{p}`" for p in pkgs[:40])
                lines.append(
                    f"- **Packages (full list: {len(pkgs)}):** {preview}, …"
                )
        else:
            lines.append("- **Packages:** —")
        lines.append(
            "- **Files / paths:** "
            + (", ".join(f"`{f}`" for f in files) if files else "—")
        )
        if notes:
            lines.append(f"- **Routing notes:** {notes[:300]}")
        err = str(row.get("error") or "").strip()
        if err:
            lines.append(f"- **Probe error:** {err[:160]}")
        lines.append("")
    return "\n".join(lines)


def enrich_facts_from_access_rows(
    facts: Any,
    host: str,
    access_rows: list[dict[str, Any]] | None,
) -> Any:
    """Merge reachable inventory endpoints into host facts for framework detect.

    Access probe already knows ``kind=pg`` / port ``5432`` is up even when
    checklist-filled ``listening_ports`` / binaries missed PostgreSQL.

    Args:
        facts: :class:`~auditor.host_facts.HostFacts`-like object (mutated).
        host: SSH / inventory IP for this host.
        access_rows: Rows from :func:`~auditor.access_probe.probe_access_endpoints`.

    Returns:
        The same ``facts`` object after enrichment.
    """
    if facts is None or not host:
        return facts
    ports: set[int] = set()
    for p in getattr(facts, "listening_ports", None) or []:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            continue
    binaries = [
        str(b).strip()
        for b in (getattr(facts, "binaries", None) or [])
        if str(b).strip()
    ]
    bins_l = {b.lower() for b in binaries}
    want = str(host).strip()
    for row in access_rows or []:
        if str(row.get("host") or "").strip() != want:
            continue
        status = str(row.get("status") or "").strip().lower()
        if status not in {"accessible", "ok", "up", "open", "reachable"}:
            continue
        try:
            port = int(str(row.get("port") or "").strip())
        except (TypeError, ValueError):
            port = 0
        if 1 <= port <= 65535:
            ports.add(port)
        kind = str(row.get("kind") or "").strip().lower()
        if kind == "pg" or port == 5432:
            ports.add(5432)
            for name in ("postgres", "psql"):
                if name not in bins_l:
                    binaries.append(name)
                    bins_l.add(name)
    try:
        facts.listening_ports = sorted(ports)
        facts.binaries = binaries
    except AttributeError:
        pass
    return facts


def format_host_access_list_markdown(
    rows: list[dict[str, Any]],
    *,
    language: str = "en",
    proposed_jobs: list[dict[str, Any]] | None = None,
) -> str:
    """Render intake step-3 table: service / IP / port / status / frameworks.

    Args:
        rows: Dicts with ``service`` (hostname or Access label), ``host``,
            ``port``, ``status``, optional ``frameworks``.
        language: ``en`` or Russian when starting with ``ru``.
        proposed_jobs: Optional host→framework rows; matched to access rows by IP.

    Returns:
        Markdown table, or a short empty-state line.
    """
    ru = (language or "en").startswith("ru")
    if not rows:
        return (
            "_Нет строк доступа в inventory._"
            if ru
            else "_No access endpoints found in inventory._"
        )
    fw_by_host: dict[str, list[str]] = {}
    for job in proposed_jobs or []:
        host = str(job.get("ssh_host") or "").strip()
        if not host:
            continue
        fws = [str(x).strip() for x in (job.get("frameworks") or []) if str(x).strip()]
        if fws:
            fw_by_host[host] = fws
    if ru:
        lines = [
            "### Доступность хостов / сервисов",
            "",
            "| Hostname / Service | IP | Порт | Статус | Применимые фреймворки |",
            "|--------------------|----|------|--------|------------------------|",
        ]
    else:
        lines = [
            "### Host / service reachability",
            "",
            "| Hostname / Service | IP | Port | Status | Applicable frameworks |",
            "|--------------------|----|------|--------|-----------------------|",
        ]
    for row in rows:
        service = str(row.get("service") or row.get("hostname") or "—").strip() or "—"
        ip = str(row.get("host") or row.get("ip") or "—").strip() or "—"
        port = str(row.get("port") or "—").strip() or "—"
        status = str(row.get("status") or "—").strip() or "—"
        row_fws = [str(x).strip() for x in (row.get("frameworks") or []) if str(x).strip()]
        fws = row_fws or fw_by_host.get(ip) or []
        # PG endpoint: prefer DB frameworks when present on that host.
        if str(row.get("kind") or "").lower() == "pg" and fws:
            dbish = [f for f in fws if "postgres" in f.lower() or "pgsql" in f.lower()]
            if dbish:
                fws = dbish
        fw_txt = ", ".join(f"`{x}`" for x in fws) if fws else "—"
        lines.append(f"| {service} | `{ip}` | `{port}` | {status} | {fw_txt} |")
    lines.append("")
    return "\n".join(lines)


def format_proposed_jobs_markdown(proposed_jobs: list[dict[str, Any]]) -> str:
    """Render proposed host→framework rows for the scope intake step."""
    if not proposed_jobs:
        return "_No hosts discovered — no framework plan yet._"
    lines = [
        "### Proposed host → frameworks",
        "",
        "| Host | Hostname | Frameworks |",
        "|------|----------|------------|",
    ]
    for row in proposed_jobs:
        host = str(row.get("ssh_host") or row.get("host_id") or "—")
        hn = str(row.get("hostname") or "—")
        fws = row.get("frameworks") or []
        fw_txt = ", ".join(f"`{x}`" for x in fws) if fws else "—"
        err = str(row.get("error") or "").strip()
        if err:
            fw_txt = f"{fw_txt} _(error: {err[:80]})_".strip()
        lines.append(f"| `{host}` | {hn} | {fw_txt} |")
    lines.append("")
    return "\n".join(lines)


def extract_management_summary(report_text: str) -> str:
    """Pull the executive/management summary from a full framework report.

    Framework reports are stored as ``summary + --- + full checklist``.
    Chat delivery should use the summary only.

    Args:
        report_text: Full or partial report Markdown.

    Returns:
        Summary section, or a truncated fallback when no separator exists.
    """
    text = (report_text or "").strip()
    if not text:
        return ""
    # Drop archive / follow-up appendices if present.
    for marker in ("\n## Audit archive", "\n---\n\n**Next steps"):
        if marker in text:
            text = text.split(marker, 1)[0].rstrip()
    # Primary layout from finalize: summary before the first horizontal rule.
    if "\n---\n" in text:
        head, tail = text.split("\n---\n", 1)
        head = head.strip()
        # Prefer head when it looks like a short summary (not the checklist table).
        if head and "| REQ-" not in head and "### REQ-" not in head:
            return head
        text = tail.strip() or head
    # Fallback: keep a short lead-in without the summary table dump.
    lines = text.splitlines()
    clipped: list[str] = []
    for line in lines:
        if line.strip().startswith("## ") and "summary" not in line.lower():
            if clipped:
                break
        if "| REQ-" in line or line.strip().startswith("### REQ-"):
            break
        clipped.append(line)
        if len(clipped) >= 40:
            break
    return "\n".join(clipped).strip() or text[:2000]


def apply_scope_exclusions(
    proposed_jobs: list[dict[str, Any]],
    excluded_frameworks: set[str],
    excluded_pairs: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Return proposed jobs with excluded frameworks / pairs removed."""
    excl_fw = {x.lower() for x in excluded_frameworks}
    excl_pairs = {(h.lower(), f.lower()) for h, f in excluded_pairs}
    out: list[dict[str, Any]] = []
    for row in proposed_jobs:
        host_id = str(row.get("host_id") or "")
        ssh = str(row.get("ssh_host") or "")
        kept: list[str] = []
        for fw in row.get("frameworks") or []:
            fw_s = str(fw)
            low = fw_s.lower()
            if low in excl_fw:
                continue
            if (host_id.lower(), low) in excl_pairs or (ssh.lower(), low) in excl_pairs:
                continue
            kept.append(fw_s)
        if not kept:
            continue
        out.append({**row, "frameworks": kept})
    return out


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

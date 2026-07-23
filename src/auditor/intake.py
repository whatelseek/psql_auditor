"""Предварительный опрос (intake): клиент, доступ, план фреймворков.

Модуль ведёт **трёхшаговый опросник** перед checklist-аудитом (если intake
включён). Собирает название клиента, доступ к серверам, затем предложение
host→framework, которое оператор может урезать. Inventory — единственный
источник хостов (без CMDB/NetBox).

Роль в пайплайне:
    Граф прерывается маркерами ``[AUDIT_INTAKE:<thread>]`` между шагами.
    Шаг 1 — детерминированный; шаги 2–3 разбираются только из JSON LLM
    (без regex-fallback на пути intake).

Ключевые точки входа:
    :func:`prompts_for_language` — локализованные промпты шагов (EN/RU).
    :func:`format_intake_assistant_message` — маркер intake в чате.
    :func:`resolve_client_name` — детерминированный шаг 1 (без LLM).
    :func:`resolve_yes_no` / :func:`resolve_audit_type`
    / :func:`resolve_scope_decision` — только JSON LLM для шагов 2–3.
    :func:`frameworks_for_audit_type` — домен → id фреймворков
    (fallback без доступа).
    :func:`summarize_access_probe` — Markdown access-пробы.
    :class:`ScopeDecision` — результат шага confirm/exclude/include.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

# ``cis`` оставлен как алиас ``cybersecurity`` для обратной совместимости.
AuditType = Literal["cis", "cybersecurity", "it", "both"]
YesNo = Literal["yes", "no", "unknown"]


@dataclass(frozen=True, slots=True)
class IntakePrompts:
    """Локализованные Markdown-промпты для каждого шага опросника intake.

    Attributes:
        client: Шаг 1 — название клиента / организации.
        cmdb: Устарело (CMDB/NetBox удалён); пустая строка для совместимости.
        access: Шаг 2 — доступ SSH/сервисов для пробы.
        scope: Шаг 3 — подтвердить / исключить / оставить только host→framework.
        audit_type: Fallback шага 3 без плана хостов — выбор домена.
    """

    client: str
    cmdb: str
    access: str
    scope: str
    audit_type: str


def client_slug(name: str) -> str:
    """Сформировать безопасный для ФС slug из отображаемого имени клиента.

    Неалфавитно-цифровые символы заменяются на ``_``, обрезка до 64 символов,
    нижний регистр. Используется для каталогов evidence и inventory.

    Args:
        name: Сырое название клиента / организации из intake.

    Returns:
        Безопасный slug; ``"client"``, если после очистки пусто.
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
    """Сопоставить короткий ярлык/токен с yes/no/unknown (без free-form regex)."""
    token = str(value or "").strip().lower().strip(".,!;:")
    if not token:
        return "unknown"
    if token in _YES_ANSWERS:
        return "yes"
    if token in _NO_ANSWERS:
        return "no"
    return "unknown"


def resolve_yes_no(text: str, llm_payload: dict[str, Any] | None = None) -> YesNo:
    """Разобрать ответ о наличии только из JSON LLM intake (шаги 2–3).

    Модель интерпретации решает yes/no/unknown. Хелпер лишь нормализует
    ярлык ``answer`` (в т.ч. сленг вроде ``ага``). Сырой текст оператора
    по regex не разбирается.

    Args:
        text: Сырой ответ (не используется; для совместимости вызовов).
        llm_payload: Dict от модели интерпретации с ключом ``answer``.

    Returns:
        ``"yes"``, ``"no"`` или ``"unknown"``.
    """
    del text
    if not isinstance(llm_payload, dict):
        return "unknown"
    return _normalize_yes_no_token(str(llm_payload.get("answer") or ""))


def intake_clarification_from_payload(
    llm_payload: dict[str, Any] | None,
) -> str:
    """Извлечь текст уточнения, если оператор задал вопрос.

    Интерпретатор да/нет может вернуть ``clarification`` (или ``help``) с
    пояснением текущего шага intake (например, ответ «что это?»).

    Args:
        llm_payload: JSON от модели интерпретации intake.

    Returns:
        Урезанный Markdown-уточнение или пустая строка.
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
    """Определить имя клиента детерминированно (шаг 1 intake — без LLM).

    ``llm_payload`` игнорируется; оставлен для совместимости вызовов.

    Args:
        text: Сырой ответ оператора.
        llm_payload: Не используется (шаг 1 — только парсер).

    Returns:
        Урезанное имя клиента (макс. 120 символов) или пустая строка.
    """
    del llm_payload
    return parse_client_name(text)


def resolve_audit_type(
    text: str, llm_payload: dict[str, Any] | None = None
) -> AuditType | None:
    """Определить домен аудита только из JSON LLM (шаг 4 intake).

    Без regex-fallback. Алиасы ``cis`` / ``cyber`` → ``cybersecurity``.

    Args:
        text: Сырой ответ (не используется; для совместимости вызовов).
        llm_payload: Dict с ключом ``audit_type`` от модели интерпретации.

    Returns:
        ``"it"``, ``"cybersecurity"``, ``"both"`` или ``None``, если неясно.
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


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """Результат разбора ответа оператора на шаге scope.

    Attributes:
        action: ``confirm`` | ``exclude`` | ``include``.
        selected_jobs: План после применения действия (может быть пустым).
    """

    action: Literal["confirm", "exclude", "include"]
    selected_jobs: list[dict[str, Any]]


def _parse_fw_id_list(raw: Any) -> set[str]:
    """Нормализовать список id фреймворков из JSON LLM."""
    return {
        str(x).strip().lower()
        for x in (raw or [])
        if str(x).strip()
    }


def _parse_host_fw_pairs(raw: Any) -> set[tuple[str, str]]:
    """Нормализовать пары host/framework из JSON LLM (строки или списки)."""
    pairs: set[tuple[str, str]] = set()
    for pair in raw or []:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
            pairs.add((str(pair[0]).strip().lower(), str(pair[1]).strip().lower()))
        elif isinstance(pair, str) and "/" in pair:
            host, fw = pair.split("/", 1)
            pairs.add((host.strip().lower(), fw.strip().lower()))
    return {(h, f) for h, f in pairs if h and f}


def host_framework_pairs(jobs: list[dict[str, Any]]) -> set[tuple[str, str]]:
    """Множество ``(host_id, framework)`` из списка proposed/selected jobs."""
    return {
        (str(row.get("host_id") or ""), str(fw))
        for row in jobs
        for fw in (row.get("frameworks") or [])
    }


def resolve_scope_decision(
    text: str,
    proposed_jobs: list[dict[str, Any]],
    llm_payload: dict[str, Any] | None = None,
) -> ScopeDecision | None:
    """Выбрать задания только из JSON LLM (шаг scope intake).

    Без regex-fallback. Неясный / отсутствующий payload → ``None`` (повтор вопроса).

    Actions:
        ``confirm`` — принять текущий план как есть.
        ``exclude`` — убрать указанные фреймворки / пары.
        ``include`` — оставить только указанные фреймворки / пары.

    После ``exclude`` / ``include`` граф показывает обновлённый план и снова
    ждёт ``confirm`` (не стартует оценку сразу).

    Returns:
        :class:`ScopeDecision` или ``None``, если ответ неясен.
        ``selected_jobs`` может быть пустым (вызывающий должен переспросить).
    """
    del text
    if not isinstance(llm_payload, dict):
        return None
    action = str(llm_payload.get("action") or "").strip().lower()
    if action in {"confirm", "all", "run_all", "accept"}:
        return ScopeDecision(
            "confirm", [dict(r) for r in proposed_jobs]
        )
    if action in {"exclude", "trim"}:
        return ScopeDecision(
            "exclude",
            apply_scope_exclusions(
                proposed_jobs,
                _parse_fw_id_list(llm_payload.get("exclude_frameworks")),
                _parse_host_fw_pairs(llm_payload.get("exclude_pairs")),
            ),
        )
    if action in {"include", "only", "keep"}:
        incl_fw = _parse_fw_id_list(llm_payload.get("include_frameworks"))
        incl_pairs = _parse_host_fw_pairs(llm_payload.get("include_pairs"))
        if not incl_fw and not incl_pairs:
            return None
        return ScopeDecision(
            "include",
            apply_scope_inclusions(proposed_jobs, incl_fw, incl_pairs),
        )
    return None


def parse_client_name(text: str) -> str:
    """Извлечь имя клиента из свободного текста, убрав типичные префиксы.

    Удаляет ведущие шаблоны вроде «Client:», «клиент:» и т.п.

    Args:
        text: Ответ оператора на шаг имени клиента.

    Returns:
        Урезанное имя (макс. 120 символов) или пустая строка.
    """
    raw = (text or "").strip()
    # Убрать типичные префиксы
    raw = re.sub(
        r"^(client(\s+name)?|клиент|название)\s*[:=-]?\s*",
        "",
        raw,
        flags=re.I,
    ).strip()
    return raw[:120] if raw else ""


def domains_for_audit_type(audit_type: AuditType | str) -> list[str]:
    """Сопоставить область intake со значениями ``domain`` фреймворков.

    Args:
        audit_type: Одно из ``it``, ``cybersecurity``, ``cis`` или ``both``.

    Returns:
        Список строк domain для маршрутизации фреймворков (один или два).
    """
    at = (audit_type or "both").strip().lower()
    if at in {"it"}:
        return ["it"]
    if at in {"cis", "cybersecurity", "cyber"}:
        return ["cybersecurity"]
    return ["it", "cybersecurity"]


def prompts_for_language(code: str) -> IntakePrompts:
    """Вернуть локализованные промпты шагов intake по коду языка.

    Args:
        code: Код BCP-47 / ISO; русский, если начинается с ``ru``.

    Returns:
        :class:`IntakePrompts` с Markdown для шагов опросника.
    """
    if (code or "en").startswith("ru"):
        return IntakePrompts(
            client=(
                "## Предварительный опрос (1/3)\n\n"
                "Укажите **название клиента** (организация / проект)."
            ),
            cmdb="",
            access=(
                "## Предварительный опрос (2/3)\n\n"
                "Есть ли у меня **доступ к серверам и сервисам** для проверки?\n\n"
                "Опишите ситуацию своими словами "
                "(например: «SSH на .79», «ты можешь туда попасть», "
                "«пока только документы»).\n\n"
                "Если доступ есть, будет показана таблица досягаемости "
                "(сервис / IP / порт / статус / применимые фреймворки)."
            ),
            scope=(
                "## Предварительный опрос (3/3)\n\n"
                "Ниже — предложенный план **хост → фреймворки**.\n\n"
                "- **Подтвердить** / **все** — запустить **текущий** план как есть.\n"
                "- **Исключить** что-то — опишите своими словами; покажем "
                "обновлённый план и попросим подтвердить перед стартом.\n"
                "- **Только** некоторые фреймворки — тоже ок "
                "(например: «только postgres_cis»).\n"
            ),
            audit_type=(
                "## Предварительный опрос (3/3)\n\n"
                "Живой план хостов недоступен (нет доступа / нет хостов в inventory).\n\n"
                "Какой **домен** аудита провести?\n\n"
                "Опишите своими словами "
                "(например: «только IT», «кибербезопасность / CIS», «и то и другое»)."
            ),
        )
    return IntakePrompts(
        client=(
            "## Pre-audit intake (1/3)\n\n"
            "What is the **client name** (organization / engagement)?"
        ),
        cmdb="",
        access=(
            "## Pre-audit intake (2/3)\n\n"
            "Do I have **access to servers and services** to probe?\n\n"
            "Describe the situation in your own words "
            "(e.g. \"SSH on .79\", \"you can get in\", \"docs only for now\").\n\n"
            "If access is available, I will list host/service reachability "
            "(service / IP / port / status / applicable frameworks)."
        ),
        scope=(
            "## Pre-audit intake (3/3)\n\n"
            "Below is the proposed **host → frameworks** plan.\n\n"
            "- **Confirm** / **all** — run the **current** plan as shown.\n"
            "- **Exclude** items — describe in your own words; we will show "
            "the updated plan and ask you to confirm before starting.\n"
            "- **Only** some frameworks — also OK "
            "(e.g. \"postgres_cis only\").\n"
        ),
        audit_type=(
            "## Pre-audit intake (3/3)\n\n"
            "No live host plan is available (no access / no inventory hosts).\n\n"
            "Which audit **domain** should I run?\n\n"
            "Describe it in your own words "
            "(e.g. \"IT only\", \"cybersecurity / CIS\", \"both\")."
        ),
    )


def format_discovered_software_markdown(
    proposed_jobs: list[dict[str, Any]],
    *,
    language: str = "en",
) -> str:
    """Сформировать prerun-инвентарь ПО для выбора фреймворков аудита.

    Args:
        proposed_jobs: Строки хостов с ``binaries``, ``packages``,
            ``key_files``, ``os_pretty_name``.
        language: ``en`` или русский при префиксе ``ru``.

    Returns:
        Markdown-секции по хостам или текст пустого состояния.
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
    """Дополнить факты хоста достижимыми endpoint'ами inventory для detect.

    Access-проба уже знает, что ``kind=pg`` / порт ``5432`` доступен, даже если
    в ``listening_ports`` / binaries PostgreSQL не попал.

    Args:
        facts: Объект вроде :class:`~auditor.host_facts.HostFacts` (мутируется).
        host: SSH / IP хоста из inventory.
        access_rows: Строки из :func:`~auditor.access_probe.probe_access_endpoints`.

    Returns:
        Тот же объект ``facts`` после обогащения.
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
    """Таблица шага 3 intake: сервис / IP / порт / статус / фреймворки.

    Args:
        rows: Dict с ``service`` (hostname или Access), ``host``,
            ``port``, ``status``, опционально ``frameworks``.
        language: ``en`` или русский при префиксе ``ru``.
        proposed_jobs: Опциональные host→framework; сопоставление по IP.

    Returns:
        Markdown-таблица или короткая строка пустого состояния.
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
        # PG endpoint: предпочитать DB-фреймворки, если они есть на хосте.
        if str(row.get("kind") or "").lower() == "pg" and fws:
            dbish = [f for f in fws if "postgres" in f.lower() or "pgsql" in f.lower()]
            if dbish:
                fws = dbish
        fw_txt = ", ".join(f"`{x}`" for x in fws) if fws else "—"
        lines.append(f"| {service} | `{ip}` | `{port}` | {status} | {fw_txt} |")
    lines.append("")
    return "\n".join(lines)


def format_proposed_jobs_markdown(proposed_jobs: list[dict[str, Any]]) -> str:
    """Сформировать строки host→framework для шага scope intake."""
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
    """Выделить executive/management summary из полного отчёта фреймворка.

    Отчёты хранятся как ``summary + --- + full checklist``.
    В чат отдаём только summary.

    Args:
        report_text: Полный или частичный Markdown отчёта.

    Returns:
        Секция summary или урезанный fallback без разделителя.
    """
    text = (report_text or "").strip()
    if not text:
        return ""
    # Убрать приложения archive / follow-up, если есть.
    for marker in ("\n## Audit archive", "\n---\n\n**Next steps"):
        if marker in text:
            text = text.split(marker, 1)[0].rstrip()
    # Основной layout finalize: summary до первого горизонтального правила.
    if "\n---\n" in text:
        head, tail = text.split("\n---\n", 1)
        head = head.strip()
        # Брать head, если это короткий summary (не таблица checklist).
        if head and "| REQ-" not in head and "### REQ-" not in head:
            return head
        text = tail.strip() or head
    # Fallback: короткое вступление без дампа таблицы summary.
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


def _apply_scope_filter(
    proposed_jobs: list[dict[str, Any]],
    frameworks: set[str],
    pairs: set[tuple[str, str]],
    *,
    mode: Literal["exclude", "include"],
) -> list[dict[str, Any]]:
    """Отфильтровать фреймворки по режиму exclude (убрать) или include (оставить)."""
    fw_set = {x.lower() for x in frameworks}
    pair_set = {(h.lower(), f.lower()) for h, f in pairs}
    out: list[dict[str, Any]] = []
    for row in proposed_jobs:
        host_id = str(row.get("host_id") or "")
        ssh = str(row.get("ssh_host") or "")
        host_keys = {host_id.lower(), ssh.lower()} - {""}
        kept: list[str] = []
        for fw in row.get("frameworks") or []:
            fw_s = str(fw)
            low = fw_s.lower()
            pair_hit = any((h, low) in pair_set for h in host_keys)
            fw_hit = low in fw_set
            if mode == "exclude":
                if fw_hit or pair_hit:
                    continue
                kept.append(fw_s)
            elif fw_hit or pair_hit:
                kept.append(fw_s)
        if kept:
            out.append({**row, "frameworks": kept})
    return out


def apply_scope_exclusions(
    proposed_jobs: list[dict[str, Any]],
    excluded_frameworks: set[str],
    excluded_pairs: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Вернуть proposed jobs без исключённых фреймворков / пар."""
    return _apply_scope_filter(
        proposed_jobs, excluded_frameworks, excluded_pairs, mode="exclude"
    )


def apply_scope_inclusions(
    proposed_jobs: list[dict[str, Any]],
    included_frameworks: set[str],
    included_pairs: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Вернуть proposed jobs, оставив только указанные фреймворки / пары."""
    return _apply_scope_filter(
        proposed_jobs, included_frameworks, included_pairs, mode="include"
    )


def format_intake_assistant_message(prompt: str, thread_id: str) -> str:
    """Обернуть промпт шага intake маркером ``[AUDIT_INTAKE:<thread>]``.

    Args:
        prompt: Markdown вопроса из :func:`prompts_for_language`.
        thread_id: Id потока LangGraph для resume.

    Returns:
        Сообщение ассистента с маркером и подсказкой продолжения.
    """
    return (
        f"{prompt.strip()}\n\n"
        f"---\n"
        f"[AUDIT_INTAKE:{thread_id}]\n"
        f"_Paused for intake. Your next message continues this questionnaire._\n"
    )





def intake_interrupt_payload(*, step: str, prompt: str, **extra: Any) -> dict[str, Any]:
    """Собрать dict payload interrupt LangGraph для шага intake.

    Args:
        step: Идентификатор шага (например ``client``, ``cmdb``).
        prompt: Текст вопроса оператору.
        **extra: Доп. поля, сливаемые в payload.

    Returns:
        Dict с ``type``, ``step``, ``prompt`` и любыми extra-ключами.
    """
    return {"type": "intake", "step": step, "prompt": prompt, **extra}


def summarize_access_probe(probe: dict[str, Any], *, language: str = "en") -> str:
    """Сформировать Markdown-таблицу результатов access-пробы.

    Args:
        probe: Dict со списком ``services``: ``name`` / ``status`` / ``detail``.
        language: ``"en"`` или русский при префиксе ``ru``.

    Returns:
        Markdown-секция о достижимости сервисов.
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
    """Упорядоченные id фреймворков по домену intake (NLP fallback без хостов).

    После discovery предпочтителен host-driven ``select_frameworks_for_host``;
    этот хелпер — для fallback без intake / без SSH.
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
    # both: сначала IT, затем cybersecurity-фреймворки
    cis_ids = frameworks_for_audit_type(
        "cybersecurity", user_request=user_request, agents_dir=agents_dir
    )
    return ["it_audit", *[i for i in cis_ids if i != "it_audit"]]

"""Предварительный опрос (intake): клиент, доступ, план фреймворков.

Модуль ведёт **трёхшаговый опросник** перед checklist-аудитом (если intake
включён). Собирает название клиента, доступ к серверам, затем предложение
host→framework, которое оператор может урезать. Inventory — единственный
источник хостов (без CMDB-интеграций).

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
    :func:`parse_audit_plan_markdown` / :func:`load_client_audit_plan` —
    операторский ``PLAN.md`` (хост → фреймворки) на шаге scope.
    :func:`frameworks_for_audit_type` — домен → id фреймворков
    (fallback без доступа).
    :func:`summarize_access_probe` — Markdown access-пробы.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

# ``cis`` оставлен как алиас ``cybersecurity`` для обратной совместимости.
AuditType = Literal["cis", "cybersecurity", "it", "both"]
YesNo = Literal["yes", "no", "unknown"]
_ENUMERATION_FRAMEWORK_PREFIXES = ("host_facts",)


@dataclass(frozen=True, slots=True)
class IntakePrompts:
    """Локализованные Markdown-промпты для каждого шага опросника intake.

    Attributes:
        client: Шаг 1 — название клиента / организации.
        cmdb: Устарело (CMDB удалён); пустая строка для совместимости.
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


def resolve_scope_decision(
    text: str,
    proposed_jobs: list[dict[str, Any]],
    llm_payload: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | None:
    """Выбрать задания только из JSON LLM (шаг scope intake).

    Без regex-fallback. Неясный / отсутствующий payload → ``None`` (повтор вопроса).

    Actions:
        ``confirm`` — принять текущий план как есть.
        ``exclude`` — убрать указанные фреймворки / пары.
        ``include`` — оставить только указанные фреймворки / пары.

    После ``exclude`` / ``include`` граф показывает обновлённый план и снова
    ждёт ``confirm`` (не стартует оценку сразу).

    Returns:
        Отфильтрованный список заданий или ``None``, если ответ неясен.
        Пустой список — всё исключено (вызывающий должен переспросить).
    """
    del text
    if not isinstance(llm_payload, dict):
        return None
    action = str(llm_payload.get("action") or "").strip().lower()
    if action in {"confirm", "all", "run_all", "accept"}:
        return normalize_scope_jobs([dict(r) for r in proposed_jobs])
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
        return normalize_scope_jobs(
            apply_scope_exclusions(proposed_jobs, excl_fw, excl_pairs)
        )
    if action in {"include", "only", "keep"}:
        incl_fw = {
            str(x).strip().lower()
            for x in (llm_payload.get("include_frameworks") or [])
            if str(x).strip()
        }
        incl_pairs: set[tuple[str, str]] = set()
        for pair in llm_payload.get("include_pairs") or []:
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                incl_pairs.add((str(pair[0]).lower(), str(pair[1]).lower()))
            elif isinstance(pair, str) and "/" in pair:
                h, f = pair.split("/", 1)
                incl_pairs.add((h.strip().lower(), f.strip().lower()))
        if not incl_fw and not incl_pairs:
            return None
        out: list[dict[str, Any]] = []
        for row in proposed_jobs:
            host_id = str(row.get("host_id") or "")
            ssh = str(row.get("ssh_host") or "")
            host_keys = {host_id.lower(), ssh.lower()} - {""}
            kept: list[str] = []
            for fw in row.get("frameworks") or []:
                fw_s = str(fw)
                low = fw_s.lower()
                pair_hit = any((h, low) in incl_pairs for h in host_keys)
                fw_hit = low in incl_fw
                if pair_hit or fw_hit:
                    kept.append(fw_s)
            if kept:
                out.append({**row, "frameworks": kept})
        return normalize_scope_jobs(out)
    return None


def is_enumeration_framework_id(framework_id: str) -> bool:
    """Return True when framework id is discovery-only and not auditable scope."""
    low = str(framework_id or "").strip().lower()
    if not low:
        return False
    return any(
        low == prefix or low.startswith(prefix + "_")
        for prefix in _ENUMERATION_FRAMEWORK_PREFIXES
    )


def filter_scope_framework_ids(framework_ids: list[str]) -> list[str]:
    """Drop discovery-only frameworks and deduplicate while preserving order."""
    out: list[str] = []
    seen: set[str] = set()
    for fw in framework_ids or []:
        fw_s = str(fw).strip()
        if not fw_s or is_enumeration_framework_id(fw_s):
            continue
        key = fw_s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(fw_s)
    return out


def normalize_scope_jobs(proposed_jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize scope rows by removing discovery-only frameworks and empty rows."""
    out: list[dict[str, Any]] = []
    for row in proposed_jobs or []:
        kept = filter_scope_framework_ids(
            [str(x) for x in (row.get("frameworks") or [])]
        )
        if not kept:
            continue
        out.append({**row, "frameworks": kept})
    return out


_PLAN_FILE_NAMES = ("PLAN.md", "AUDIT_PLAN.md", "SCOPE.md", "plan.md")
_HOST_HEADER_TOKENS = frozenset(
    {
        "host",
        "hosts",
        "hostip",
        "ip",
        "ips",
        "target",
        "targets",
        "hostname",
        "address",
        "server",
        "хост",
        "адрес",
        "сервер",
    }
)
_FW_HEADER_TOKENS = frozenset(
    {
        "framework",
        "frameworks",
        "check",
        "checks",
        "checklist",
        "audit",
        "audits",
        "scope",
        "фреймворк",
        "фреймворки",
        "проверки",
        "проверка",
    }
)
_BULLET_PLAN = re.compile(
    r"^\s*[-*•]\s*`?(?P<host>[A-Za-z0-9._:-]+)`?\s*[=:→\-]+\s*(?P<rest>.+)$"
)
_TABLE_ROW = re.compile(r"^\|(.+)\|$")


def _host_slug(host: str) -> str:
    """Filesystem-safe host id (same idea as inventory SSH slug)."""
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", (host or "").strip()).strip("._-")
    return raw or "host"


def _norm_plan_header(cell: str) -> str:
    """Normalize a plan-table header for column detection."""
    return re.sub(r"[^a-z0-9а-яё]+", "", (cell or "").lower())


def _split_framework_ids(text: str) -> list[str]:
    """Split a frameworks/checks cell into framework ids."""
    raw = (text or "").strip()
    if not raw or raw in {"—", "-", "–"}:
        return []
    parts = re.split(r"[,;/|]+|\s+", raw)
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        fid = part.strip().strip("`").strip()
        if not fid or fid.lower() in {"and", "и", "plus", "+"}:
            continue
        key = fid.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(fid)
    return out


def _job_row(host: str, frameworks: list[str]) -> dict[str, Any]:
    """Build one proposed/selected job dict from host + framework ids."""
    host_s = (host or "").strip()
    return {
        "host_id": _host_slug(host_s),
        "hostname": "",
        "ssh_host": host_s,
        "frameworks": list(frameworks),
        "error": "",
        "plan_source": "markdown",
    }


def parse_audit_plan_markdown(
    text: str,
    *,
    known_framework_ids: set[str] | frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Parse an operator Markdown audit plan into host→framework jobs.

    Accepts a pipe table (Host | Frameworks / Checks) or bullet lines
    (``- 10.0.0.10: postgres_cis, ubuntu_cis_24_l2``).

    Args:
        text: Markdown body (file contents or chat paste).
        known_framework_ids: Optional allow-list; unknown tokens are dropped
            when provided. When ``None``, all non-empty tokens are kept.

    Returns:
        Job rows compatible with intake ``proposed_jobs`` / ``selected_jobs``.
        Empty list when no plan rows are found.
    """
    known = (
        {x.lower() for x in known_framework_ids}
        if known_framework_ids is not None
        else None
    )
    lines = (text or "").splitlines()
    by_host: dict[str, list[str]] = {}
    host_labels: dict[str, str] = {}

    def _add(host: str, fws: list[str]) -> None:
        host_s = (host or "").strip().strip("`")
        if not host_s:
            return
        kept: list[str] = []
        for fw in fws:
            if is_enumeration_framework_id(fw):
                continue
            if known is not None and fw.lower() not in known:
                continue
            if fw.lower() not in {x.lower() for x in kept}:
                kept.append(fw)
        if not kept:
            return
        key = host_s.lower()
        host_labels.setdefault(key, host_s)
        cur = by_host.setdefault(key, [])
        for fw in kept:
            if fw.lower() not in {x.lower() for x in cur}:
                cur.append(fw)

    # Table path
    for i, line in enumerate(lines):
        match = _TABLE_ROW.match(line.strip())
        if not match:
            continue
        cells = [c.strip() for c in match.group(1).split("|")]
        norms = [_norm_plan_header(c) for c in cells]
        host_col = next(
            (
                j
                for j, h in enumerate(norms)
                if h in _HOST_HEADER_TOKENS
                or "host" in h
                or h in {"ip", "ips"}
            ),
            None,
        )
        fw_col = next(
            (
                j
                for j, h in enumerate(norms)
                if h in _FW_HEADER_TOKENS
                or "framework" in h
                or "check" in h
                or "фрейм" in h
            ),
            None,
        )
        if host_col is None or fw_col is None:
            continue
        for line2 in lines[i + 1 :]:
            stripped = line2.strip()
            if not stripped.startswith("|"):
                if by_host:
                    break
                continue
            if re.match(r"^\|[\s|:-]+\|$", stripped):
                continue
            body = [c.strip() for c in stripped.strip("|").split("|")]
            if len(body) <= max(host_col, fw_col):
                body.extend([""] * (max(host_col, fw_col) + 1 - len(body)))
            host = body[host_col] if host_col < len(body) else ""
            fws = _split_framework_ids(body[fw_col] if fw_col < len(body) else "")
            _add(host, fws)
        break

    # Bullet path when no table rows
    if not by_host:
        for line in lines:
            m = _BULLET_PLAN.match(line)
            if not m:
                continue
            _add(m.group("host"), _split_framework_ids(m.group("rest")))

    return [_job_row(host_labels[k], fws) for k, fws in by_host.items()]


def load_client_audit_plan(
    inventory_dir: Path | str,
    client_slug_name: str,
    *,
    agents_dir: Path | str | None = None,
) -> tuple[list[dict[str, Any]], Path | None]:
    """Load ``PLAN.md`` / ``AUDIT_PLAN.md`` / ``SCOPE.md`` from client inventory.

    Args:
        inventory_dir: Inventory root.
        client_slug_name: Client folder slug.
        agents_dir: Optional frameworks dir to validate ids.

    Returns:
        ``(jobs, path)`` — jobs may be empty; ``path`` is the file used or
        ``None`` when no plan file exists.
    """
    from auditor.host_facts import resolve_client_dir

    client_dir = resolve_client_dir(Path(inventory_dir), client_slug_name)
    known: set[str] | None = None
    if agents_dir is not None:
        from auditor.frameworks import list_frameworks

        known = {fw.id.lower() for fw in list_frameworks(agents_dir)}
        # Also accept common aliases from frontmatter via list — ids only is fine

    for name in _PLAN_FILE_NAMES:
        path = client_dir / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        jobs = parse_audit_plan_markdown(text, known_framework_ids=known)
        if jobs:
            return jobs, path
        # File exists but empty/unparsed — still report path for operator hint
        return [], path
    return [], None


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
                "- Или вставьте / положите в inventory таблицу "
                "``PLAN.md``: Host | Frameworks.\n"
            ),
            audit_type=(
                "## Предварительный опрос (3/3)\n\n"
                "Живой план хостов недоступен (нет доступа / нет хостов в inventory).\n\n"
                "Какой **домен** аудита провести?\n\n"
                "Опишите своими словами "
                "(например: «только IT», «кибербезопасность / CIS», «и то и другое»), "
                "или вставьте Markdown-таблицу Host | Frameworks / положите "
                "``PLAN.md`` в каталог клиента."
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
            "- Or paste / place ``PLAN.md`` in the client inventory: "
            "Host | Frameworks table.\n"
        ),
        audit_type=(
            "## Pre-audit intake (3/3)\n\n"
            "No live host plan is available (no access / no inventory hosts).\n\n"
            "Which audit **domain** should I run?\n\n"
            "Describe it in your own words "
            "(e.g. \"IT only\", \"cybersecurity / CIS\", \"both\"), "
            "or paste a Markdown Host | Frameworks table / put ``PLAN.md`` "
            "in the client inventory folder."
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
        elif kind == "mysql" or port == 3306:
            ports.add(3306)
            for name in ("mysql", "mysqld"):
                if name not in bins_l:
                    binaries.append(name)
                    bins_l.add(name)
        elif kind == "oracle" or port == 1521:
            ports.add(1521)
            for name in ("oracle", "sqlplus"):
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
            ``port``, ``status``, опционально ``detail`` и ``frameworks``.
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
        detail = str(row.get("detail") or "").strip()
        status_txt = f"{status} ({detail[:80]})" if detail else status
        row_fws = [str(x).strip() for x in (row.get("frameworks") or []) if str(x).strip()]
        fws = row_fws or fw_by_host.get(ip) or []
        # PG endpoint: предпочитать DB-фреймворки, если они есть на хосте.
        if str(row.get("kind") or "").lower() == "pg" and fws:
            dbish = [f for f in fws if "postgres" in f.lower() or "pgsql" in f.lower()]
            if dbish:
                fws = dbish
        fw_txt = ", ".join(f"`{x}`" for x in fws) if fws else "—"
        lines.append(f"| {service} | `{ip}` | `{port}` | {status_txt} | {fw_txt} |")
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


def apply_scope_exclusions(
    proposed_jobs: list[dict[str, Any]],
    excluded_frameworks: set[str],
    excluded_pairs: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Вернуть proposed jobs без исключённых фреймворков / пар."""
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
    return normalize_scope_jobs(out)


def format_intake_assistant_message(prompt: str, thread_id: str) -> str:
    """Обернуть промпт шага intake скрытым маркером resume-потока.

    Args:
        prompt: Markdown вопроса из :func:`prompts_for_language`.
        thread_id: Id потока LangGraph для resume.

    Returns:
        Сообщение ассистента без служебного текста для оператора.
    """
    # Keep intake resume marker machine-readable but hidden from chat UI.
    return f"{prompt.strip()}\n\n<!-- AUDIT_INTAKE:{thread_id} -->\n"





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
        ids = filter_scope_framework_ids(ids)
        ids = [i for i in ids if i != "it_audit"]
        if not ids:
            all_fw = list_frameworks(agents_dir)
            ids = [f.id for f in all_fw if f.id.endswith("_cis") or "cis" in f.id]
            ids = filter_scope_framework_ids(ids)
        return ids or ["postgres_cis"]
    # both: сначала IT, затем cybersecurity-фреймворки
    cis_ids = frameworks_for_audit_type(
        "cybersecurity", user_request=user_request, agents_dir=agents_dir
    )
    return ["it_audit", *[i for i in cis_ids if i != "it_audit"]]

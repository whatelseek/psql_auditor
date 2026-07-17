"""Response language selection for operator-facing text.

The agent answers in the language the user asks for. **Russian is the
default** when no language is requested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ISO-ish codes we localize UI strings for; others fall back to English UI
# with an LLM instruction to use that language name.
DEFAULT_LANGUAGE = "ru"

_EXPLICIT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:in|on)\s+english\b|\benglish\s+please\b|"
            r"\brespond\s+in\s+english\b|\banswer\s+in\s+english\b|"
            r"\bна\s+английском\b|\bпо[- ]?английски\b",
            re.I,
        ),
        "en",
    ),
    (
        re.compile(
            r"\b(?:in|on)\s+russian\b|\brussian\s+please\b|"
            r"\brespond\s+in\s+russian\b|\banswer\s+in\s+russian\b|"
            r"\bна\s+русском\b|\bпо[- ]?русски\b",
            re.I,
        ),
        "ru",
    ),
    (
        re.compile(
            r"\b(?:in|on)\s+spanish\b|\ben\s+espa[nñ]ol\b|\bна\s+испанском\b",
            re.I,
        ),
        "es",
    ),
    (
        re.compile(
            r"\b(?:in|on)\s+german\b|\bauf\s+deutsch\b|\bна\s+немецком\b",
            re.I,
        ),
        "de",
    ),
    (
        re.compile(
            r"\b(?:in|on)\s+french\b|\ben\s+fran[cç]ais\b|\bна\s+французском\b",
            re.I,
        ),
        "fr",
    ),
    (
        re.compile(
            r"\b(?:in|on)\s+chinese\b|\bна\s+китайском\b|\b用中文\b",
            re.I,
        ),
        "zh",
    ),
]

_LANGUAGE_NAMES = {
    "ru": "Russian",
    "en": "English",
    "es": "Spanish",
    "de": "German",
    "fr": "French",
    "zh": "Chinese",
}

_CYRILLIC = re.compile(r"[А-Яа-яЁё]")
_LATIN = re.compile(r"[A-Za-z]")


@dataclass(frozen=True, slots=True)
class ResponseLanguage:
    """Resolved operator response language."""

    code: str  # e.g. ru, en
    name: str  # English name for LLM instructions

    @property
    def llm_instruction(self) -> str:
        return (
            f"Write all operator-facing prose in **{self.name}** "
            f"(language code: {self.code}). "
            "Keep machine fields unchanged: status values must stay "
            "`pass|fail|partial|error|skipped`; tool names, SQL, and shell "
            "commands stay as-is."
        )


def language_from_code(code: str | None, *, default: str = DEFAULT_LANGUAGE) -> ResponseLanguage:
    """Build a ``ResponseLanguage`` from a stored code."""
    resolved = (code or default or DEFAULT_LANGUAGE).strip().lower() or DEFAULT_LANGUAGE
    return ResponseLanguage(
        code=resolved,
        name=_LANGUAGE_NAMES.get(resolved, resolved),
    )


def detect_response_language(
    user_text: str,
    *,
    default: str = DEFAULT_LANGUAGE,
) -> ResponseLanguage:
    """Pick response language from the user request.

    Priority:
    1. Explicit request (\"in English\", \"на русском\", …)
    2. Mostly Cyrillic user text → Russian
    3. ``default`` (Russian unless configured otherwise)
    """
    text = user_text or ""
    for pattern, code in _EXPLICIT_PATTERNS:
        if pattern.search(text):
            return ResponseLanguage(code=code, name=_LANGUAGE_NAMES.get(code, code))

    cyr = len(_CYRILLIC.findall(text))
    lat = len(_LATIN.findall(text))
    if cyr >= 12 and cyr >= lat:
        return ResponseLanguage(code="ru", name="Russian")

    code = (default or DEFAULT_LANGUAGE).strip().lower() or DEFAULT_LANGUAGE
    return ResponseLanguage(code=code, name=_LANGUAGE_NAMES.get(code, code))


def ui(lang: ResponseLanguage | str, key: str, **fmt: object) -> str:
    """Look up a localized UI string (falls back to English, then key)."""
    code = lang.code if isinstance(lang, ResponseLanguage) else str(lang)
    table = _UI.get(code) or _UI["en"]
    template = table.get(key) or _UI["en"].get(key) or key
    return template.format(**fmt) if fmt else template


_UI: dict[str, dict[str, str]] = {
    "ru": {
        "hitl_title": "## Не удалось проверить `{req_id}`",
        "hitl_framework": "**Фреймворк:** `{framework_id}`",
        "hitl_requirement": "**Требование:** {title}",
        "hitl_category": "**Категория:** {category} | **Критичность:** {severity}",
        "hitl_why": "### Почему",
        "hitl_pass": "### Критерии прохождения",
        "hitl_how": "### Как проверить (чеклист)",
        "hitl_reco": "### Рекомендации",
        "hitl_evidence": "**Папка с доказательствами:** `{evidence_dir}`",
        "hitl_what": "### Что сделать?",
        "hitl_reply": "Ответьте одним из вариантов:",
        "hitl_opt_skip": "- **skip** / **пропустить** — пропустить это требование и продолжить",
        "hitl_opt_retry": "- **retry** / **повторить** — попробовать проверить снова",
        "hitl_opt_skip_all": "- **skip all** / **пропустить все** — пропустить все оставшиеся ошибки",
        "hitl_opt_retry_all": "- **retry all** / **повторить все** — повторить все оставшиеся ошибки",
        "hitl_paused": "_Пауза для решения оператора. Следующее сообщение продолжит аудит._",
        "hitl_unknown": (
            "Не понял ответ.\n\n"
            "Ответьте **skip** / **пропустить**, **retry** / **повторить**, "
            "**skip all** или **retry all**.\n\n"
        ),
        "no_evidence": "Доказательства не собраны.",
        "archive_title": "## Архив аудита",
        "archive_body": "📦 Отчёт и доказательства упакованы в **`{name}`** ({size_kb} КБ).",
        "archive_download": "**[Скачать ZIP]({download_url})**",
        "archive_owui": "Также файл в Open WebUI: **[Открыть архив]({owui_path})**",
        "archive_click": (
            '<a href="{download_url}" download>'
            "Нажмите здесь, если Markdown-ссылка не скачивает файл</a>"
        ),
        "stream_start": (
            "Запускаю аудит для {count} фреймворк(ов): {names} "
            "(параллельных REQ={workers}; HITL={hitl})…\n\n"
        ),
        "stream_resume": "Возобновляю приостановленный аудит (`{thread}`)…\n\n",
        "stream_hitl": "Пауза: нужно ваше решение (skip / retry)…\n\n",
        "stream_zip": "Упаковываю ZIP-архив аудита…\n\n",
        "stream_route_err": "Ошибка маршрутизации: {exc}\n",
        "stream_audit_err": "\n\nОшибка аудита: {exc}\n",
        "summary_failed": "(Не удалось сформировать резюме: {exc})",
        "finalize_system": (
            "Вы пишете краткие executive summary для отчётов аудита безопасности. "
            "Пишите на русском языке, если не указано иное."
        ),
        "multi_progress_title": "# Мультифреймворк-аудит (в процессе)",
        "multi_completed": "Уже завершено до паузы: {ids}",
        "multi_waiting": "Сейчас ожидание по: `{current_id}`",
    },
    "en": {
        "hitl_title": "## Could not audit `{req_id}`",
        "hitl_framework": "**Framework:** `{framework_id}`",
        "hitl_requirement": "**Requirement:** {title}",
        "hitl_category": "**Category:** {category} | **Severity:** {severity}",
        "hitl_why": "### Why",
        "hitl_pass": "### Pass criteria",
        "hitl_how": "### How to verify (checklist)",
        "hitl_reco": "### Recommendations",
        "hitl_evidence": "**Evidence folder:** `{evidence_dir}`",
        "hitl_what": "### What should I do?",
        "hitl_reply": "Reply with one of:",
        "hitl_opt_skip": "- **skip** — mark this requirement as skipped and continue",
        "hitl_opt_retry": "- **retry** — try auditing this requirement again",
        "hitl_opt_skip_all": "- **skip all** — skip all remaining failed requirements",
        "hitl_opt_retry_all": "- **retry all** — retry all remaining failed requirements",
        "hitl_paused": "_Paused for human decision. Your next message resumes this audit._",
        "hitl_unknown": (
            "I didn't understand that reply.\n\n"
            "Please answer with **skip**, **retry**, **skip all**, or **retry all**.\n\n"
        ),
        "no_evidence": "No evidence collected.",
        "archive_title": "## Audit archive",
        "archive_body": "📦 Report + evidence packaged as **`{name}`** ({size_kb} KB).",
        "archive_download": "**[Download ZIP]({download_url})**",
        "archive_owui": "Also attached in Open WebUI files: **[Open archive]({owui_path})**",
        "archive_click": (
            '<a href="{download_url}" download>'
            "Click here if the markdown link does not download</a>"
        ),
        "stream_start": (
            "Starting audit for {count} framework(s): {names} "
            "(REQ workers={workers}; HITL={hitl})…\n\n"
        ),
        "stream_resume": "Resuming paused audit (`{thread}`)…\n\n",
        "stream_hitl": "Paused for your decision (skip / retry).\n\n",
        "stream_zip": "Packaging audit ZIP for download…\n\n",
        "stream_route_err": "Routing error: {exc}\n",
        "stream_audit_err": "\n\nAudit error: {exc}\n",
        "summary_failed": "(Summary generation failed: {exc})",
        "finalize_system": (
            "You write short executive summaries for fixed-format "
            "security audit reports across OS/DB frameworks."
        ),
        "multi_progress_title": "# Multi-framework audit (in progress)",
        "multi_completed": "Completed before pause: {ids}",
        "multi_waiting": "Now waiting on: `{current_id}`",
    },
}

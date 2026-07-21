"""Detect and apply the operator's preferred report language (English or Russian)."""

from __future__ import annotations

import re
from dataclasses import dataclass

_ALLOWED = frozenset({"en", "ru"})


@dataclass(frozen=True, slots=True)
class ReportLanguage:
    """Resolved language for narrative report cells and localized UI labels."""

    code: str
    """Short code used for UI packs (``en`` or ``ru``)."""

    name: str
    """Human language name for LLM instructions (``English`` or ``Russian``)."""


# Explicit "write the report in X" / "на русском" style requests.
_EXPLICIT_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\b(in|on)\s+english\b", re.I), "en", "English"),
    (re.compile(r"\b(in|on)\s+russian\b", re.I), "ru", "Russian"),
    (re.compile(r"\breport\s+(language|lang)\s*[:=]?\s*([a-z]{2,})\b", re.I), "", ""),
    (
        re.compile(
            r"(на\s+русском|по[- ]?русски|язык\s*[:=]?\s*русск)",
            re.I,
        ),
        "ru",
        "Russian",
    ),
    (
        re.compile(
            r"(на\s+английском|по[- ]?английски|язык\s*[:=]?\s*англ)",
            re.I,
        ),
        "en",
        "English",
    ),
)

_CODE_TO_NAME = {
    "en": "English",
    "ru": "Russian",
}

_NAME_TO_CODE = {
    "english": "en",
    "russian": "ru",
    "английский": "en",
    "русский": "ru",
}

# Localized fixed-report chrome (section titles / column headers).
# Narrative cells still come from the LLM in ``ReportLanguage.name``.
_REPORT_UI: dict[str, dict[str, str]] = {
    "en": {
        "fixed_format_note": (
            "Fixed report format — checklist fields are immutable; the model fills "
            "**Status**, **Observation**, and **Recommendation** only."
        ),
        "assessed": "Assessed",
        "requirements": "requirements",
        "summary_table": "Summary table",
        "requirement_details": "Requirement details",
        "col_id": "ID",
        "col_title": "Title",
        "col_severity": "Severity",
        "col_status": "Status",
        "col_observation": "Observation",
        "col_recommendation": "Recommendation",
        "col_cell": "Cell",
        "col_value": "Value",
        "category": "Category",
        "pass_criteria": "Pass criteria",
        "how_to_verify": "How to verify",
        "status": "Status",
        "observation": "Observation",
        "recommendation": "Recommendation",
        "pass": "pass",
        "fail": "fail",
        "partial": "partial",
        "error": "error",
        "skipped": "skipped",
        "chart_title": "CIS compliance by severity (%)",
        "chart_heading": "CIS compliance visualization",
        "chart_overall": "Overall compliance",
        "chart_formula": (
            "(pass + ½·partial / assessed; skipped excluded from denominator)."
        ),
        "chart_parse_fail": "Could not parse findings from the report markdown.",
        "chart_sev": "Severity",
        "chart_pct": "Compliance %",
        "chart_total": "Total",
        "chart_overall_label": "Overall",
    },
    "ru": {
        "fixed_format_note": (
            "Фиксированный формат отчёта — поля чеклиста неизменяемы; модель "
            "заполняет только **Статус**, **Наблюдение** и **Рекомендацию**."
        ),
        "assessed": "Оценено",
        "requirements": "требований",
        "summary_table": "Сводная таблица",
        "requirement_details": "Детали по требованиям",
        "col_id": "ID",
        "col_title": "Название",
        "col_severity": "Критичность",
        "col_status": "Статус",
        "col_observation": "Наблюдение",
        "col_recommendation": "Рекомендация",
        "col_cell": "Ячейка",
        "col_value": "Значение",
        "category": "Категория",
        "pass_criteria": "Критерий прохождения",
        "how_to_verify": "Как проверить",
        "status": "Статус",
        "observation": "Наблюдение",
        "recommendation": "Рекомендация",
        "pass": "pass",
        "fail": "fail",
        "partial": "partial",
        "error": "error",
        "skipped": "skipped",
        "chart_title": "Соответствие CIS по критичности (%)",
        "chart_heading": "Визуализация соответствия CIS",
        "chart_overall": "Общий уровень соответствия",
        "chart_formula": (
            "(pass + ½·partial / оценённые; skipped не входят в знаменатель)."
        ),
        "chart_parse_fail": "Не удалось разобрать таблицу результатов в отчёте.",
        "chart_sev": "Критичность",
        "chart_pct": "Соответствие %",
        "chart_total": "Всего",
        "chart_overall_label": "Overall",
    },
}


def normalize_language_code(value: str) -> str:
    """Return ``en`` or ``ru``; anything else falls back to ``en``."""
    text = (value or "").strip().lower().replace("_", "-")
    if not text:
        return "en"
    if text in _ALLOWED:
        return text
    if text in _NAME_TO_CODE:
        return _NAME_TO_CODE[text]
    primary = text.split("-", 1)[0]
    if primary in _ALLOWED:
        return primary
    return "en"


def language_name(code: str) -> str:
    code = normalize_language_code(code)
    return _CODE_TO_NAME.get(code, "English")


def report_ui(language: str | ReportLanguage | None) -> dict[str, str]:
    code = (
        language.code
        if isinstance(language, ReportLanguage)
        else normalize_language_code(str(language or "en"))
    )
    code = normalize_language_code(code)
    return _REPORT_UI.get(code, _REPORT_UI["en"])


def detect_report_language(user_request: str) -> ReportLanguage:
    """Pick English or Russian from an explicit request or Cyrillic wording."""
    text = user_request or ""

    for pattern, code, name in _EXPLICIT_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        if code:
            return ReportLanguage(code=code, name=name)
        # ``report language: ru`` style capture — only en/ru accepted.
        token = (match.group(2) if match.lastindex and match.lastindex >= 2 else "").lower()
        token = normalize_language_code(token)
        return ReportLanguage(code=token, name=language_name(token))

    # Cyrillic operator wording → Russian; otherwise English.
    if re.search(r"[\u0400-\u04FF]", text):
        return ReportLanguage(code="ru", name="Russian")

    return ReportLanguage(code="en", name="English")


def language_instruction(language: str | ReportLanguage | None) -> str:
    """Prompt fragment forcing narrative cells into English or Russian."""
    if isinstance(language, ReportLanguage):
        code = normalize_language_code(language.code)
        name = language_name(code)
    else:
        name = language_name(str(language or "en"))
    return (
        f"Write all narrative report text in **{name}** only "
        f"(English or Russian are the supported languages): executive summary, "
        f"observation, and recommendation. Keep status tokens as "
        f"pass|fail|partial|error|skipped. Keep requirement IDs (REQ-NNN) and "
        f"technical identifiers/paths unchanged."
    )

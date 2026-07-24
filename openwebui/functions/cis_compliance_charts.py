"""
title: CIS Compliance Charts
author: auditor
author_url: https://github.com/whatelseek/psql_auditor
funding_url: https://github.com/whatelseek/psql_auditor
version: 0.1.0
license: MIT
description: Visualize CIS / auditor Markdown report compliance by severity as % bar charts (SVG).
required_open_webui_version: 0.4.0
"""

from __future__ import annotations

import base64
import re
from collections import defaultdict
from typing import Any, Iterable

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Parser + SVG (self-contained for Open WebUI Admin → Functions install)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info", "Unknown")
_STATUS_PASS = {"pass", "passed", "ok", "compliant"}
_STATUS_PARTIAL = {"partial", "warning", "warn"}
_SUMMARY_ROW = re.compile(
    r"^\|\s*(REQ-\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|",
    re.IGNORECASE | re.MULTILINE,
)
_COLORS = {
    "Critical": "#b91c1c",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#2563eb",
    "Info": "#64748b",
    "Unknown": "#6b7280",
    "Overall": "#0f766e",
}


def _norm_sev(raw: str) -> str:
    """Normalize a severity label to canonical title case.

    Args:
        raw: Raw severity string from a Markdown table or detail block.

    Returns:
        One of ``Critical``, ``High``, ``Medium``, ``Low``, ``Info``, or
        ``Unknown``. Unrecognized values are title-cased or default to ``Unknown``.
    """
    key = (raw or "").strip().lower()
    return {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
        "unknown": "Unknown",
    }.get(key, (raw or "Unknown").strip() or "Unknown")


def _norm_status(raw: str) -> str:
    """Normalize audit status text to a small internal vocabulary.

    Args:
        raw: Raw status cell from the summary table or detail block (may include
            Markdown bold markers).

    Returns:
        Lowercase token: ``pass``, ``partial``, ``fail``, ``error``, ``skipped``,
        or the stripped original when unrecognized.
    """
    text = (raw or "").strip().lower().replace("**", "").strip()
    if text in _STATUS_PASS:
        return "pass"
    if text in _STATUS_PARTIAL:
        return "partial"
    if text in {"fail", "failed", "non-compliant", "noncompliant"}:
        return "fail"
    if text in {"error", "err"}:
        return "error"
    if text in {"skipped", "skip", "n/a", "na"}:
        return "skipped"
    return text or "error"


def parse_findings(markdown: str) -> list[dict[str, str]]:
    """Extract requirement rows from an auditor Markdown report.

    Tries the summary table first (``| REQ-NNN | … | Severity | Status |``). If no
    rows match, falls back to per-requirement ``### REQ-NNN`` detail sections.

    Args:
        markdown: Full audit report Markdown.

    Returns:
        List of dicts with keys ``req_id``, ``title``, ``severity``, and
        ``status``. Duplicate ``req_id`` values are ignored (first wins).
    """
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in _SUMMARY_ROW.finditer(markdown or ""):
        rid = m.group(1).upper()
        if rid in seen:
            continue
        seen.add(rid)
        rows.append(
            {
                "req_id": rid,
                "title": m.group(2).strip(),
                "severity": _norm_sev(m.group(3)),
                "status": _norm_status(m.group(4)),
            }
        )
    if rows:
        return rows
    detail = re.finditer(
        r"###\s+(REQ-\d+)\s*:\s*(.+?)\n(.*?)(?=\n###\s+REQ-|\n##\s+|\Z)",
        markdown or "",
        re.I | re.S,
    )
    for block in detail:
        rid = block.group(1).upper()
        if rid in seen:
            continue
        body = block.group(3)
        sev_m = re.search(r"\|\s*Severity\s*\|\s*([^|]+)\|", body, re.I)
        st_m = re.search(r"\|\s*\*\*Status\*\*\s*\|\s*([^|]+)\|", body, re.I)
        if not st_m:
            continue
        seen.add(rid)
        rows.append(
            {
                "req_id": rid,
                "title": block.group(2).strip(),
                "severity": _norm_sev(sev_m.group(1) if sev_m else ""),
                "status": _norm_status(st_m.group(1)),
            }
        )
    return rows


def _pct(passed: int, partial: int, assessed: int) -> float:
    """Compute weighted compliance percentage.

    Partial passes count as half a pass: ``(passed + 0.5 * partial) / assessed``.

    Args:
        passed: Count of passing requirements.
        partial: Count of partial/warning requirements.
        assessed: Denominator (total minus skipped).

    Returns:
        Percentage rounded to one decimal place, or ``0.0`` when ``assessed <= 0``.
    """
    if assessed <= 0:
        return 0.0
    return round(100.0 * (passed + 0.5 * partial) / assessed, 1)


def compliance_stats(rows: Iterable[dict[str, str]]) -> list[dict[str, Any]]:
    """Aggregate finding counts and compliance % per severity bucket.

    Args:
        rows: Parsed findings from :func:`parse_findings` (must include
            ``severity`` and ``status`` keys).

    Returns:
        List of stat dicts ordered by :data:`_SEVERITY_ORDER`, each containing
        ``severity``, count fields (``total``, ``passed``, ``partial``, etc.),
        and ``percent``. Skipped items are excluded from the percent denominator.
    """
    buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "passed": 0,
            "partial": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
        }
    )
    for row in rows:
        b = buckets[row["severity"]]
        b["total"] += 1
        st = row["status"]
        if st == "pass":
            b["passed"] += 1
        elif st == "partial":
            b["partial"] += 1
        elif st == "skipped":
            b["skipped"] += 1
        elif st == "error":
            b["errors"] += 1
        else:
            b["failed"] += 1

    out: list[dict[str, Any]] = []
    used: set[str] = set()
    for sev in _SEVERITY_ORDER:
        if sev not in buckets:
            continue
        used.add(sev)
        b = buckets[sev]
        assessed = b["total"] - b["skipped"]
        out.append(
            {
                "severity": sev,
                **b,
                "percent": _pct(b["passed"], b["partial"], assessed),
            }
        )
    for sev, b in sorted(buckets.items()):
        if sev in used:
            continue
        assessed = b["total"] - b["skipped"]
        out.append(
            {
                "severity": sev,
                **b,
                "percent": _pct(b["passed"], b["partial"], assessed),
            }
        )
    return out


def overall_stats(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Compute a single overall compliance bucket across all severities.

    Args:
        rows: Parsed findings from :func:`parse_findings`.

    Returns:
        Stat dict with ``severity`` set to ``"Overall"`` and the same count /
        ``percent`` fields as :func:`compliance_stats`. Returns zeroed counts when
        ``rows`` is empty.
    """
    fake = [{**r, "severity": "Overall"} for r in rows]
    stats = compliance_stats(fake)
    return stats[0] if stats else {
        "severity": "Overall",
        "total": 0,
        "passed": 0,
        "partial": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "percent": 0.0,
    }


def _xml(text: str) -> str:
    """Escape text for safe inclusion in SVG ``<text>`` elements.

    Args:
        text: Raw label or title string.

    Returns:
        XML-escaped string (``&``, ``<``, ``>``, ``"``).
    """
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_svg(stats: list[dict[str, Any]], title: str) -> str:
    """Render a horizontal bar chart as an inline SVG string.

    Args:
        stats: Per-severity (or overall) stat dicts from :func:`compliance_stats`
            or :func:`overall_stats`; each must include ``severity`` and
            ``percent``.
        title: Chart heading displayed at the top.

    Returns:
        Complete SVG document. When ``stats`` is empty, returns a minimal
        "No findings" placeholder SVG.
    """
    width, bar_h, gap = 640, 28, 14
    if not stats:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="80">'
            f'<text x="16" y="40" fill="#64748b">No findings</text></svg>'
        )
    left, right, top = 110, 56, 44
    chart_w = width - left - right
    height = top + len(stats) * (bar_h + gap) + 24
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#0b1220"/>',
        f'<text x="16" y="28" fill="#e2e8f0" font-size="16" '
        f'font-family="system-ui,sans-serif">{_xml(title)}</text>',
    ]
    for tick in (0, 25, 50, 75, 100):
        x = left + chart_w * (tick / 100.0)
        parts.append(
            f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{height - 16}" '
            f'stroke="#1e293b"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{height - 4}" fill="#64748b" font-size="10" '
            f'text-anchor="middle" font-family="system-ui,sans-serif">{tick}%</text>'
        )
    for i, row in enumerate(stats):
        y = top + i * (bar_h + gap)
        color = _COLORS.get(row["severity"], "#64748b")
        bar_w = max(0.0, min(chart_w, chart_w * (float(row["percent"]) / 100.0)))
        assessed = row["total"] - row["skipped"]
        parts.append(
            f'<text x="{left - 10}" y="{y + bar_h * 0.7:.1f}" fill="#cbd5e1" '
            f'font-size="13" text-anchor="end" font-family="system-ui,sans-serif">'
            f'{_xml(row["severity"])}</text>'
        )
        parts.append(
            f'<rect x="{left}" y="{y}" width="{chart_w}" height="{bar_h}" '
            f'rx="6" fill="#1e293b"/>'
        )
        parts.append(
            f'<rect x="{left}" y="{y}" width="{bar_w:.1f}" height="{bar_h}" '
            f'rx="6" fill="{color}"/>'
        )
        label = (
            f'{row["percent"]:.1f}%  '
            f'({row["passed"]}+½·{row["partial"]}/{assessed} assessed)'
        )
        parts.append(
            f'<text x="{left + 8}" y="{y + bar_h * 0.7:.1f}" fill="#f8fafc" '
            f'font-size="12" font-family="system-ui,sans-serif">{_xml(label)}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def svg_as_markdown_image(svg: str, *, alt: str = "CIS compliance chart") -> str:
    """Embed SVG as a base64 Markdown image for Open WebUI rendering.

    Open WebUI's Markdown sanitizer often strips raw ``<svg>`` tags; a
    ``data:image/svg+xml;base64,...`` image is displayed reliably.

    Args:
        svg: Raw SVG document string.
        alt: Alt text for the Markdown image.

    Returns:
        Markdown image line: ``![alt](data:image/svg+xml;base64,...)``.
    """
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"![{alt}](data:image/svg+xml;base64,{b64})"


def build_visualization(report_markdown: str, *, language: str = "en") -> str:
    """Build the full CIS compliance visualization Markdown block.

    Parses findings, computes per-severity and overall stats, renders an SVG bar
    chart, and appends a summary table plus embedded chart image.

    Args:
        report_markdown: Full auditor report Markdown.
        language: ``"en"`` or ``"ru"`` for labels and error messages.

    Returns:
        Markdown section with heading, compliance table, and base64 SVG image.
        Returns a short error string when no REQ rows can be parsed.
    """
    rows = parse_findings(report_markdown)
    if not rows:
        return (
            "Не удалось разобрать REQ-строки в отчёте."
            if language.startswith("ru")
            else "Could not parse REQ rows from the report."
        )
    by_sev = compliance_stats(rows)
    overall = overall_stats(rows)
    chart_stats = [overall, *by_sev]
    title = (
        "Соответствие CIS по критичности (%)"
        if language.startswith("ru")
        else "CIS compliance by severity (%)"
    )
    svg = render_svg(chart_stats, title)
    image = svg_as_markdown_image(svg, alt=title)
    if language.startswith("ru"):
        lines = [
            "## Визуализация соответствия CIS",
            "",
            f"**Общий уровень:** **{overall['percent']:.1f}%** "
            "(pass + ½·partial / оценённые; skipped не в знаменателе).",
            "",
            "| Критичность | % | Pass | Partial | Fail | Error | Skip | Всего |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    else:
        lines = [
            "## CIS compliance visualization",
            "",
            f"**Overall compliance:** **{overall['percent']:.1f}%** "
            "(pass + ½·partial / assessed; skipped excluded).",
            "",
            "| Severity | % | Pass | Partial | Fail | Error | Skip | Total |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    for s in chart_stats:
        lines.append(
            f"| {s['severity']} | {s['percent']:.1f}% | {s['passed']} | {s['partial']} | "
            f"{s['failed']} | {s['errors']} | {s['skipped']} | {s['total']} |"
        )
    lines.extend(["", image, ""])
    return "\n".join(lines)


def _detect_lang(text: str) -> str:
    """Heuristically detect report language from character set.

    Args:
        text: Report Markdown body.

    Returns:
        ``"ru"`` when Cyrillic characters are present, otherwise ``"en"``.
    """
    if re.search(r"[А-Яа-яЁё]", text or ""):
        return "ru"
    return "en"


# ---------------------------------------------------------------------------
# Open WebUI Tools
# ---------------------------------------------------------------------------


class Tools:
    """Open WebUI Tool exposing CIS compliance chart generation.

    Registered as ``cis_compliance_charts`` with method
    ``visualize_cis_compliance``. Configure default language via nested
    :class:`Valves`.
    """

    class Valves(BaseModel):
        """User-configurable defaults for the CIS compliance chart tool.

        Attributes:
            LANGUAGE: Chart label language — ``auto`` (detect from report),
                ``en``, or ``ru``.
        """

        LANGUAGE: str = Field(
            default="auto",
            description="Chart labels language: auto | en | ru",
        )

    def __init__(self) -> None:
        """Initialize tool instance with default :class:`Valves`."""
        self.valves = self.Valves()

    def visualize_cis_compliance(
        self,
        report_markdown: str,
        language: str = "",
    ) -> str:
        """Visualize CIS / auditor Markdown report as compliance % bar charts.

        Args:
            report_markdown: Full audit report Markdown (summary table with
                Severity + Status columns, or per-REQ detail sections).
            language: Optional ``en`` or ``ru``. When empty, uses
                :attr:`Valves.LANGUAGE` or auto-detects from report text.

        Returns:
            Markdown containing a compliance summary table and an embedded SVG bar
            chart (base64 image) grouped by severity.
        """
        lang = (language or self.valves.LANGUAGE or "auto").strip().lower()
        if lang in {"", "auto"}:
            lang = _detect_lang(report_markdown)
        return build_visualization(report_markdown, language=lang)

"""CIS / auditor report compliance metrics and SVG bar charts.

Parses the fixed Markdown summary table produced by ``render_report`` and
computes compliance percentage by severity (and overall).
"""

from __future__ import annotations

import base64
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info", "Unknown")
_STATUS_PASS = {"pass", "passed", "ok", "compliant"}
_STATUS_PARTIAL = {"partial", "warning", "warn"}
# skipped excluded from denominator by default (not assessed)


@dataclass(frozen=True, slots=True)
class FindingRow:
    req_id: str
    title: str
    severity: str
    status: str


@dataclass(frozen=True, slots=True)
class SeverityCompliance:
    severity: str
    total: int
    passed: int
    partial: int
    failed: int
    errors: int
    skipped: int
    percent: float  # 0–100, based on assessed (non-skipped) rows


def normalize_severity(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return "Unknown"
    key = text.lower()
    mapping = {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
        "unknown": "Unknown",
        "—": "Unknown",
        "-": "Unknown",
    }
    return mapping.get(key, text[:1].upper() + text[1:] if text else "Unknown")


def normalize_status(raw: str) -> str:
    text = (raw or "").strip().lower()
    text = text.replace("**", "").strip()
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


_SUMMARY_ROW = re.compile(
    r"^\|\s*(REQ-\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|",
    re.IGNORECASE | re.MULTILINE,
)


def parse_report_findings(markdown: str) -> list[FindingRow]:
    """Extract finding rows from an auditor Markdown report summary table."""
    text = markdown or ""
    rows: list[FindingRow] = []
    seen: set[str] = set()
    for match in _SUMMARY_ROW.finditer(text):
        req_id = match.group(1).upper()
        if req_id in seen:
            continue
        seen.add(req_id)
        rows.append(
            FindingRow(
                req_id=req_id,
                title=match.group(2).strip(),
                severity=normalize_severity(match.group(3)),
                status=normalize_status(match.group(4)),
            )
        )
    if rows:
        return rows

    # Fallback: detail blocks "| **Status** | pass |" near ### REQ-001
    detail_blocks = re.finditer(
        r"###\s+(REQ-\d+)\s*:\s*(.+?)\n(.*?)(?=\n###\s+REQ-|\n##\s+|\Z)",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    for block in detail_blocks:
        req_id = block.group(1).upper()
        if req_id in seen:
            continue
        body = block.group(3)
        sev_m = re.search(r"\|\s*Severity\s*\|\s*([^|]+)\|", body, re.I)
        st_m = re.search(r"\|\s*\*\*Status\*\*\s*\|\s*([^|]+)\|", body, re.I)
        if not st_m:
            continue
        seen.add(req_id)
        rows.append(
            FindingRow(
                req_id=req_id,
                title=block.group(2).strip(),
                severity=normalize_severity(sev_m.group(1) if sev_m else ""),
                status=normalize_status(st_m.group(1)),
            )
        )
    return rows


def _compliance_percent(passed: int, partial: int, assessed: int) -> float:
    if assessed <= 0:
        return 0.0
    # partial counts as half-compliant
    score = passed + 0.5 * partial
    return round(100.0 * score / assessed, 1)


def compliance_by_severity(
    rows: Iterable[FindingRow],
) -> list[SeverityCompliance]:
    """Aggregate compliance % per severity bucket."""
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
        b = buckets[row.severity]
        b["total"] += 1
        if row.status == "pass":
            b["passed"] += 1
        elif row.status == "partial":
            b["partial"] += 1
        elif row.status == "skipped":
            b["skipped"] += 1
        elif row.status == "error":
            b["errors"] += 1
        else:
            b["failed"] += 1

    ordered: list[SeverityCompliance] = []
    used = set()
    for sev in _SEVERITY_ORDER:
        if sev not in buckets:
            continue
        used.add(sev)
        b = buckets[sev]
        assessed = b["total"] - b["skipped"]
        ordered.append(
            SeverityCompliance(
                severity=sev,
                total=b["total"],
                passed=b["passed"],
                partial=b["partial"],
                failed=b["failed"],
                errors=b["errors"],
                skipped=b["skipped"],
                percent=_compliance_percent(b["passed"], b["partial"], assessed),
            )
        )
    for sev, b in sorted(buckets.items()):
        if sev in used:
            continue
        assessed = b["total"] - b["skipped"]
        ordered.append(
            SeverityCompliance(
                severity=sev,
                total=b["total"],
                passed=b["passed"],
                partial=b["partial"],
                failed=b["failed"],
                errors=b["errors"],
                skipped=b["skipped"],
                percent=_compliance_percent(b["passed"], b["partial"], assessed),
            )
        )
    return ordered


def overall_compliance(rows: list[FindingRow]) -> SeverityCompliance:
    """Single overall compliance metric across all severities."""
    fake = [FindingRow(r.req_id, r.title, "Overall", r.status) for r in rows]
    stats = compliance_by_severity(fake)
    return stats[0] if stats else SeverityCompliance(
        "Overall", 0, 0, 0, 0, 0, 0, 0.0
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


def render_compliance_bar_chart_svg(
    stats: list[SeverityCompliance],
    *,
    title: str = "CIS compliance by severity (%)",
    width: int = 640,
    bar_height: int = 28,
    gap: int = 14,
) -> str:
    """Render a horizontal SVG bar chart (0–100%)."""
    if not stats:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="80">'
            f'<text x="16" y="40" fill="#64748b">No findings to chart</text></svg>'
        )

    left = 110
    right = 56
    top = 44
    chart_w = width - left - right
    height = top + len(stats) * (bar_height + gap) + 24

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{_xml(title)}">',
        f'<rect width="100%" height="100%" fill="#0b1220"/>',
        f'<text x="16" y="28" fill="#e2e8f0" font-size="16" font-family="system-ui,sans-serif">'
        f"{_xml(title)}</text>",
    ]

    # grid lines at 0/25/50/75/100
    for tick in (0, 25, 50, 75, 100):
        x = left + chart_w * (tick / 100.0)
        parts.append(
            f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{height - 16}" '
            f'stroke="#1e293b" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{height - 4}" fill="#64748b" font-size="10" '
            f'text-anchor="middle" font-family="system-ui,sans-serif">{tick}%</text>'
        )

    for i, row in enumerate(stats):
        y = top + i * (bar_height + gap)
        color = _COLORS.get(row.severity, "#64748b")
        bar_w = max(0.0, min(chart_w, chart_w * (row.percent / 100.0)))
        parts.append(
            f'<text x="{left - 10}" y="{y + bar_height * 0.7:.1f}" fill="#cbd5e1" '
            f'font-size="13" text-anchor="end" font-family="system-ui,sans-serif">'
            f"{_xml(row.severity)}</text>"
        )
        parts.append(
            f'<rect x="{left}" y="{y}" width="{chart_w}" height="{bar_height}" '
            f'rx="6" fill="#1e293b"/>'
        )
        parts.append(
            f'<rect x="{left}" y="{y}" width="{bar_w:.1f}" height="{bar_height}" '
            f'rx="6" fill="{color}"/>'
        )
        label = (
            f"{row.percent:.1f}%  "
            f"({row.passed}+½·{row.partial}/{row.total - row.skipped} assessed)"
        )
        parts.append(
            f'<text x="{left + 8}" y="{y + bar_height * 0.7:.1f}" fill="#f8fafc" '
            f'font-size="12" font-family="system-ui,sans-serif">{_xml(label)}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def svg_as_markdown_image(svg: str, *, alt: str = "CIS compliance chart") -> str:
    """Embed SVG as Markdown image for Open WebUI / common Markdown viewers."""
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"![{alt}](data:image/svg+xml;base64,{b64})"


def _xml(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def format_compliance_markdown(
    markdown_report: str,
    *,
    title: str = "CIS compliance by severity (%)",
    language: str = "en",
) -> str:
    """Parse report → markdown section with table + SVG chart."""
    rows = parse_report_findings(markdown_report)
    if not rows:
        if language.startswith("ru"):
            return (
                "\n\n---\n\n## Визуализация соответствия CIS\n\n"
                "Не удалось разобрать таблицу результатов в отчёте.\n"
            )
        return (
            "\n\n---\n\n## CIS compliance visualization\n\n"
            "Could not parse findings from the report markdown.\n"
        )

    by_sev = compliance_by_severity(rows)
    overall = overall_compliance(rows)
    chart_stats = [
        SeverityCompliance(
            "Overall",
            overall.total,
            overall.passed,
            overall.partial,
            overall.failed,
            overall.errors,
            overall.skipped,
            overall.percent,
        ),
        *by_sev,
    ]
    svg = render_compliance_bar_chart_svg(chart_stats, title=title)
    image = svg_as_markdown_image(svg, alt=title)

    if language.startswith("ru"):
        lines = [
            "",
            "---",
            "",
            "## Визуализация соответствия CIS",
            "",
            f"**Общий уровень соответствия:** **{overall.percent:.1f}%** "
            f"(pass + ½·partial / оценённые; skipped не входят в знаменатель).",
            "",
            "| Критичность | Соответствие % | Pass | Partial | Fail | Error | Skip | Всего |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    else:
        lines = [
            "",
            "---",
            "",
            "## CIS compliance visualization",
            "",
            f"**Overall compliance:** **{overall.percent:.1f}%** "
            f"(pass + ½·partial / assessed; skipped excluded from denominator).",
            "",
            "| Severity | Compliance % | Pass | Partial | Fail | Error | Skip | Total |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]

    for s in chart_stats:
        lines.append(
            f"| {s.severity} | {s.percent:.1f}% | {s.passed} | {s.partial} | "
            f"{s.failed} | {s.errors} | {s.skipped} | {s.total} |"
        )

    lines.extend(["", image, ""])
    return "\n".join(lines)

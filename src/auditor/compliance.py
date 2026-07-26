"""CIS / auditor report compliance metrics and SVG bar charts.

Post-processing stage run at finalize time when
``Settings.compliance_charts_in_report`` is enabled. Parses the fixed Markdown
summary table produced by :func:`auditor.state.render_report`, computes
compliance percentage by severity (and overall), and appends a table plus
embedded SVG chart via :func:`format_compliance_markdown`.

Skipped requirements are excluded from the compliance denominator by default.
Partial findings count as half-compliant in the percentage formula.
"""

from __future__ import annotations

import base64
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from auditor.language import ReportLanguage, report_ui
from auditor.state import Finding, aggregate_findings

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info", "Unknown")
_STATUS_PASS = {"pass", "passed", "ok", "compliant"}
_STATUS_PARTIAL = {"partial", "warning", "warn"}
# skipped excluded from denominator by default (not assessed)


@dataclass(frozen=True, slots=True)
class FindingRow:
    """One parsed row from an audit report summary or detail block.

    Attributes:
        req_id: Requirement id (``REQ-NNN``).
        title: Requirement title from the report table.
        severity: Normalized severity bucket (Critical, High, …).
        status: Normalized status token (pass, fail, partial, error, skipped).
    """

    req_id: str
    title: str
    severity: str
    status: str


@dataclass(frozen=True, slots=True)
class SeverityCompliance:
    """Aggregated compliance statistics for one severity bucket.

    Attributes:
        severity: Severity label or ``Overall`` for the rollup row.
        total: Total findings in this bucket (including skipped).
        passed: Count with status ``pass``.
        partial: Count with status ``partial``.
        failed: Count with status ``fail``.
        errors: Count with status ``error``.
        skipped: Count with status ``skipped``.
        percent: Compliance percentage 0–100 based on assessed (non-skipped) rows.
    """

    severity: str
    total: int
    passed: int
    partial: int
    failed: int
    errors: int
    skipped: int
    percent: float  # 0–100, based on assessed (non-skipped) rows


def findings_to_compliance_metrics(
    findings: Mapping[str, Finding],
) -> dict[str, Any]:
    """Derive status counts + overall compliance % from filled findings.

    Used by the results Postgres warehouse when upserting ``host_results``.

    Args:
        findings: Mapping of requirement id to :class:`~auditor.state.Finding`.

    Returns:
        Dict with keys ``pass``, ``fail``, ``partial``, ``error``, ``skipped``,
        ``assessed``, and ``compliance_pct``.
    """
    counts = aggregate_findings(dict(findings))
    rows = [
        FindingRow(
            req_id=f.requirement_id,
            title=f.title or "",
            severity=f.severity or "Unknown",
            status=f.status,
        )
        for f in findings.values()
    ]
    overall = overall_compliance(rows)
    assessed = max(0, overall.total - overall.skipped)
    return {
        "pass": counts.get("pass", 0),
        "fail": counts.get("fail", 0),
        "partial": counts.get("partial", 0),
        "error": counts.get("error", 0),
        "skipped": counts.get("skipped", 0),
        "assessed": assessed,
        "compliance_pct": float(overall.percent),
    }


def normalize_severity(raw: str) -> str:
    """Map free-form severity text to a canonical bucket name.

    Args:
        raw: Severity string from a report table cell.

    Returns:
        One of Critical, High, Medium, Low, Info, Unknown, or title-cased input.
    """
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
    """Map free-form status text to a canonical assessment token.

    Strips Markdown bold markers and recognizes common synonyms (e.g. ``ok`` →
    ``pass``, ``non-compliant`` → ``fail``).

    Args:
        raw: Status string from a report table or detail block.

    Returns:
        One of ``pass``, ``partial``, ``fail``, ``error``, ``skipped``, or the
        lowercased input (defaulting empty to ``error``).
    """
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
    """Extract finding rows from an auditor Markdown report summary table.

    Primary path: regex-scan the summary table pipe rows. Fallback: parse per-
    requirement detail blocks (``### REQ-NNN``) when the summary table is absent
    or unparsable. Supports English and Russian column headers in detail blocks.

    Args:
        markdown: Full audit report Markdown from :func:`render_report`.

    Returns:
        Deduplicated list of :class:`FindingRow` in document order.
    """
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
        sev_m = re.search(
            r"\|\s*(Severity|Критичность)\s*\|\s*([^|]+)\|",
            body,
            re.I,
        )
        st_m = re.search(
            r"\|\s*\*\*(Status|Статус)\*\*\s*\|\s*([^|]+)\|",
            body,
            re.I,
        )
        if not st_m:
            continue
        seen.add(req_id)
        rows.append(
            FindingRow(
                req_id=req_id,
                title=block.group(2).strip(),
                severity=normalize_severity(sev_m.group(2) if sev_m else ""),
                status=normalize_status(st_m.group(2)),
            )
        )
    return rows


def _compliance_percent(passed: int, partial: int, assessed: int) -> float:
    """Compute weighted compliance percentage for one bucket.

    Partial findings contribute half a point. Returns ``0.0`` when ``assessed`` is
    zero to avoid division by zero.

    Args:
        passed: Count of passing requirements.
        partial: Count of partially compliant requirements.
        assessed: Denominator (total minus skipped).

    Returns:
        Rounded percentage in the range 0.0–100.0.
    """
    if assessed <= 0:
        return 0.0
    # partial counts as half-compliant
    score = passed + 0.5 * partial
    return round(100.0 * score / assessed, 1)


def compliance_by_severity(
    rows: Iterable[FindingRow],
) -> list[SeverityCompliance]:
    """Aggregate compliance percentage per severity bucket.

    Buckets are emitted in canonical severity order (Critical → Info), then any
    unknown severities alphabetically. Skipped rows are counted but excluded from
    the percent denominator.

    Args:
        rows: Parsed finding rows from :func:`parse_report_findings`.

    Returns:
        Ordered list of :class:`SeverityCompliance` statistics.
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
    """Compute a single overall compliance metric across all severities.

    Reuses :func:`compliance_by_severity` by assigning every row the synthetic
    severity label ``Overall``.

    Args:
        rows: All parsed finding rows for the report.

    Returns:
        One :class:`SeverityCompliance` rollup, or zeros when ``rows`` is empty.
    """
    fake = [FindingRow(r.req_id, r.title, "Overall", r.status) for r in rows]
    stats = compliance_by_severity(fake)
    return stats[0] if stats else SeverityCompliance("Overall", 0, 0, 0, 0, 0, 0, 0.0)


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
    """Render a horizontal SVG bar chart (0–100%) for compliance stats.

    Produces a dark-theme chart with grid lines at 25% intervals and per-row
    labels showing percent and pass/partial/assessed counts.

    Args:
        stats: Rows to chart (typically Overall plus each severity).
        title: Chart heading embedded in the SVG.
        width: Total SVG width in pixels.
        bar_height: Height of each horizontal bar.
        gap: Vertical gap between bars.

    Returns:
        Complete SVG document as a string. Empty input yields a placeholder SVG.
    """
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
        '<rect width="100%" height="100%" fill="#0b1220"/>',
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
            f"{row.percent:.1f}%  ({row.passed}+½·{row.partial}/{row.total - row.skipped} assessed)"
        )
        parts.append(
            f'<text x="{left + 8}" y="{y + bar_height * 0.7:.1f}" fill="#f8fafc" '
            f'font-size="12" font-family="system-ui,sans-serif">{_xml(label)}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def svg_as_markdown_image(svg: str, *, alt: str = "CIS compliance chart") -> str:
    """Embed SVG as a base64 Markdown image for Open WebUI and viewers.

    Args:
        svg: Raw SVG markup.
        alt: Image alt text for accessibility.

    Returns:
        Markdown ``![alt](data:image/svg+xml;base64,…)`` string.
    """
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"![{alt}](data:image/svg+xml;base64,{b64})"


def severity_issue_counts(
    rows: Iterable[FindingRow],
) -> dict[str, int]:
    """Count non-pass findings (fail/error/partial) by severity bucket.

    Args:
        rows: Parsed report finding rows.

    Returns:
        Mapping of canonical severity label → issue count.
    """
    counts: dict[str, int] = {sev: 0 for sev in ("Critical", "High", "Medium", "Low")}
    for row in rows:
        status = normalize_status(row.status)
        if status not in {"fail", "error", "partial"}:
            continue
        sev = normalize_severity(row.severity)
        if sev not in counts:
            counts[sev] = 0
        counts[sev] += 1
    return counts


def format_severity_line(counts: Mapping[str, int]) -> str:
    """Format ``High: X; Medium: Y; Low: Z`` (include Critical when present).

    Args:
        counts: Severity → issue count mapping.

    Returns:
        Single-line Markdown-ready severity summary.
    """
    parts: list[str] = []
    for sev in ("Critical", "High", "Medium", "Low"):
        value = int(counts.get(sev) or 0)
        if sev == "Critical" and value <= 0:
            continue
        parts.append(f"{sev}: {value}")
    return "; ".join(parts) if parts else "High: 0; Medium: 0; Low: 0"


def format_status_mermaid_pie(status_counts: Mapping[str, int]) -> str:
    """Build a Mermaid pie chart for Open WebUI native rendering.

    Args:
        status_counts: Mapping with keys like pass/fail/partial/error/skipped.

    Returns:
        Fenced ``mermaid`` code block, or empty string when no data.
    """
    slices = [
        ("Pass", int(status_counts.get("pass") or 0)),
        ("Fail", int(status_counts.get("fail") or 0)),
        ("Partial", int(status_counts.get("partial") or 0)),
        ("Error", int(status_counts.get("error") or 0)),
        ("Skipped", int(status_counts.get("skipped") or 0)),
    ]
    active = [(label, n) for label, n in slices if n > 0]
    if not active:
        return ""
    lines = ["```mermaid", "pie showData", "    title Pass / Fail statistics"]
    for label, n in active:
        lines.append(f'    "{label}" : {n}')
    lines.extend(["```", ""])
    return "\n".join(lines)


def format_owui_viz_dashboard(
    *,
    status_counts: Mapping[str, int],
    severity_counts: Mapping[str, int],
    compliance_pct: float,
    hosts: int,
    total: int,
) -> str:
    """Build Inline Visualizer HTML/SVG block for Open WebUI Functions.

    Emits ``@@@VIZ-START`` / ``@@@VIZ-END`` markers used by the Inline
    Visualizer tool/filter so the summary renders as a rich UI card in chat.

    Args:
        status_counts: Pass/fail/partial/error/skipped counts.
        severity_counts: Non-pass counts by severity.
        compliance_pct: Overall compliance percentage.
        hosts: Number of audited hosts.
        total: Total requirements.

    Returns:
        Markdown-safe visualizer fragment (markers + HTML).
    """
    passed = int(status_counts.get("pass") or 0)
    failed = int(status_counts.get("fail") or 0)
    partial = int(status_counts.get("partial") or 0)
    errors = int(status_counts.get("error") or 0)
    high = int(severity_counts.get("High") or 0)
    medium = int(severity_counts.get("Medium") or 0)
    low = int(severity_counts.get("Low") or 0)
    critical = int(severity_counts.get("Critical") or 0)
    max_bar = max(failed, partial, errors, passed, 1)
    bar_w = 220

    def _bar(value: int, color: str) -> str:
        width = max(4, int(bar_w * (value / max_bar))) if value else 0
        return (
            f'<rect x="70" y="0" width="{bar_w}" height="14" rx="4" fill="#1e293b"/>'
            f'<rect x="70" y="0" width="{width}" height="14" rx="4" fill="{color}"/>'
            f'<text x="300" y="11" fill="#e2e8f0" font-size="11">{value}</text>'
        )

    svg = f"""
<svg xmlns="http://www.w3.org/2000/svg" width="360" height="150" viewBox="0 0 360 150">
  <text x="0" y="14" fill="#e2e8f0" font-size="13"
        font-family="system-ui,sans-serif">Status distribution</text>
  <g transform="translate(0,28)">
    <text x="0" y="11" fill="#94a3b8" font-size="11">Pass</text>{_bar(passed, "#16a34a")}
  </g>
  <g transform="translate(0,52)">
    <text x="0" y="11" fill="#94a3b8" font-size="11">Fail</text>{_bar(failed, "#dc2626")}
  </g>
  <g transform="translate(0,76)">
    <text x="0" y="11" fill="#94a3b8" font-size="11">Partial</text>{_bar(partial, "#ca8a04")}
  </g>
  <g transform="translate(0,100)">
    <text x="0" y="11" fill="#94a3b8" font-size="11">Error</text>{_bar(errors, "#7c3aed")}
  </g>
</svg>
""".strip()

    html = f"""
<div style="font-family:system-ui,sans-serif;color:#e2e8f0;
background:#0b1220;padding:16px;border-radius:12px;">
  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
    <div style="background:#111827;padding:10px 14px;border-radius:10px;min-width:110px;">
      <div style="color:#94a3b8;font-size:12px;">Hosts</div>
      <div style="font-size:22px;font-weight:700;">{hosts}</div>
    </div>
    <div style="background:#111827;padding:10px 14px;border-radius:10px;min-width:110px;">
      <div style="color:#94a3b8;font-size:12px;">Requirements</div>
      <div style="font-size:22px;font-weight:700;">{total}</div>
    </div>
    <div style="background:#111827;padding:10px 14px;border-radius:10px;min-width:110px;">
      <div style="color:#94a3b8;font-size:12px;">Compliance</div>
      <div style="font-size:22px;font-weight:700;">{compliance_pct:.1f}%</div>
    </div>
  </div>
  <div style="color:#cbd5e1;margin-bottom:8px;font-size:13px;">
    Critical: {critical}; High: {high}; Medium: {medium}; Low: {low}
  </div>
  {svg}
</div>
""".strip()
    return f"\n@@@VIZ-START\n{html}\n@@@VIZ-END\n"


def format_chat_summary_visuals(
    rows: Iterable[FindingRow],
    *,
    status_counts: Mapping[str, int],
    compliance_pct: float,
    hosts: int,
    total: int,
    language: str | ReportLanguage | None = "en",
) -> str:
    """Chat-ready visualization block (Mermaid + SVG + OWUI Inline Visualizer).

    Args:
        rows: Parsed finding rows for severity/compliance charts.
        status_counts: Aggregate pass/fail statistics.
        compliance_pct: Overall compliance percentage.
        hosts: Audited host count.
        total: Total requirements.
        language: Report language for SVG chart labels.

    Returns:
        Markdown fragment for the management summary chat reply.
    """
    row_list = list(rows)
    sev_counts = severity_issue_counts(row_list)
    by_sev = compliance_by_severity(row_list)
    overall = overall_compliance(row_list)
    ui = report_ui(language)
    chart_stats = [
        SeverityCompliance(
            ui["chart_overall_label"],
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
    svg = render_compliance_bar_chart_svg(
        chart_stats, title=ui.get("chart_title") or "Compliance by severity (%)"
    )
    image = svg_as_markdown_image(svg, alt=ui.get("chart_title") or "Compliance chart")
    mermaid = format_status_mermaid_pie(status_counts)
    viz = format_owui_viz_dashboard(
        status_counts=status_counts,
        severity_counts=sev_counts,
        compliance_pct=compliance_pct,
        hosts=hosts,
        total=total,
    )
    parts = [
        "",
        f"**Severity issues:** {format_severity_line(sev_counts)}",
        "",
        "## Visualization",
        "",
    ]
    if mermaid:
        parts.append(mermaid)
    parts.extend([image, "", viz])
    return "\n".join(parts)


def _xml(text: str) -> str:
    """Escape a string for safe inclusion in SVG/XML text nodes.

    Args:
        text: Raw user- or data-derived string.

    Returns:
        XML-escaped string (`&`, `<`, `>`, `"` replaced).
    """
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
    title: str | None = None,
    language: str | ReportLanguage | None = "en",
) -> str:
    """Append a compliance section (table + SVG chart) to an audit report.

    End-to-end helper: parse findings, compute per-severity and overall stats,
    render chart, and return Markdown to concatenate after the main report body.

    Args:
        markdown_report: Existing report Markdown from :func:`render_report`.
        title: Optional chart title override; defaults to localized UI string.
        language: Report language for table/chart labels.

    Returns:
        Markdown fragment (leading ``---`` separator) or a parse-failure message.
    """
    ui = report_ui(language)
    chart_title = title or ui["chart_title"]
    rows = parse_report_findings(markdown_report)
    if not rows:
        return f"\n\n---\n\n## {ui['chart_heading']}\n\n{ui['chart_parse_fail']}\n"

    by_sev = compliance_by_severity(rows)
    overall = overall_compliance(rows)
    overall_label = ui["chart_overall_label"]
    chart_stats = [
        SeverityCompliance(
            overall_label,
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
    svg = render_compliance_bar_chart_svg(chart_stats, title=chart_title)
    image = svg_as_markdown_image(svg, alt=chart_title)

    lines = [
        "",
        "---",
        "",
        f"## {ui['chart_heading']}",
        "",
        f"**{ui['chart_overall']}:** **{overall.percent:.1f}%** {ui['chart_formula']}",
        "",
        f"| {ui['chart_sev']} | {ui['chart_pct']} | Pass | Partial | Fail | "
        f"Error | Skip | {ui['chart_total']} |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for s in chart_stats:
        lines.append(
            f"| {s.severity} | {s.percent:.1f}% | {s.passed} | {s.partial} | "
            f"{s.failed} | {s.errors} | {s.skipped} | {s.total} |"
        )

    lines.extend(["", image, ""])
    return "\n".join(lines)

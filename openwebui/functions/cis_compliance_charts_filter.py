"""
title: CIS Compliance Charts (Auto Filter)
author: auditor
version: 0.1.0
license: MIT
description: Outlet filter — appends CIS compliance % bar charts to auditor Markdown reports.
required_open_webui_version: 0.4.0
"""

from __future__ import annotations

# Re-use the same module logic by importing sibling Tools file content is duplicated
# minimally here so the filter can be installed independently in Open WebUI.

import base64
import re
from collections import defaultdict
from typing import Any, Iterable, Optional

from pydantic import BaseModel, Field

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
    key = (raw or "").strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }.get(key, (raw or "Unknown").strip() or "Unknown")


def _norm_status(raw: str) -> str:
    text = (raw or "").strip().lower().replace("**", "").strip()
    if text in _STATUS_PASS:
        return "pass"
    if text in _STATUS_PARTIAL:
        return "partial"
    if text in {"fail", "failed"}:
        return "fail"
    if text in {"error", "err"}:
        return "error"
    if text in {"skipped", "skip"}:
        return "skipped"
    return text or "error"


def parse_findings(markdown: str) -> list[dict[str, str]]:
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
    return rows


def _pct(passed: int, partial: int, assessed: int) -> float:
    if assessed <= 0:
        return 0.0
    return round(100.0 * (passed + 0.5 * partial) / assessed, 1)


def compliance_stats(rows: Iterable[dict[str, str]]) -> list[dict[str, Any]]:
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
    out = []
    for sev in _SEVERITY_ORDER:
        if sev not in buckets:
            continue
        b = buckets[sev]
        assessed = b["total"] - b["skipped"]
        out.append({**b, "severity": sev, "percent": _pct(b["passed"], b["partial"], assessed)})
    return out


def overall_stats(rows: list[dict[str, str]]) -> dict[str, Any]:
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
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_svg(stats: list[dict[str, Any]], title: str) -> str:
    width, bar_h, gap = 640, 28, 14
    left, right, top = 110, 56, 44
    chart_w = width - left - right
    height = top + max(1, len(stats)) * (bar_h + gap) + 24
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
            f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{height - 16}" stroke="#1e293b"/>'
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
            f'<text x="{left - 10}" y="{y + bar_h * 0.7:.1f}" fill="#cbd5e1" font-size="13" '
            f'text-anchor="end" font-family="system-ui,sans-serif">{_xml(row["severity"])}</text>'
        )
        parts.append(
            f'<rect x="{left}" y="{y}" width="{chart_w}" height="{bar_h}" rx="6" fill="#1e293b"/>'
        )
        parts.append(
            f'<rect x="{left}" y="{y}" width="{bar_w:.1f}" height="{bar_h}" rx="6" fill="{color}"/>'
        )
        label = f'{row["percent"]:.1f}% ({row["passed"]}+½·{row["partial"]}/{assessed})'
        parts.append(
            f'<text x="{left + 8}" y="{y + bar_h * 0.7:.1f}" fill="#f8fafc" font-size="12" '
            f'font-family="system-ui,sans-serif">{_xml(label)}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def svg_as_markdown_image(svg: str, *, alt: str = "CIS compliance chart") -> str:
    """Embed SVG as a Markdown image.

    Open WebUI's Markdown path often does not render raw ``<svg>`` tags; a
    ``data:image/svg+xml;base64,...`` image is displayed reliably.
    """
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"![{alt}](data:image/svg+xml;base64,{b64})"


def build_visualization(report_markdown: str, *, language: str = "en") -> str:
    rows = parse_findings(report_markdown)
    if not rows:
        return ""
    by_sev = compliance_stats(rows)
    overall = overall_stats(rows)
    chart_stats = [overall, *by_sev]
    title = (
        "Соответствие CIS по критичности (%)"
        if language.startswith("ru")
        else "CIS compliance by severity (%)"
    )
    svg = render_svg(chart_stats, title)
    alt = title
    image = svg_as_markdown_image(svg, alt=alt)
    if language.startswith("ru"):
        lines = [
            "## Визуализация соответствия CIS",
            "",
            f"**Общий уровень:** **{overall['percent']:.1f}%**",
            "",
            "| Критичность | % | Pass | Partial | Fail | Error | Skip | Всего |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    else:
        lines = [
            "## CIS compliance visualization",
            "",
            f"**Overall compliance:** **{overall['percent']:.1f}%**",
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


def _message_text(content: Any) -> str:
    """Normalize Open WebUI message content (str or content-parts list) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if item.get("type") == "text" and item.get("text"):
                    parts.append(str(item["text"]))
                elif "content" in item:
                    parts.append(str(item.get("content") or ""))
        return "\n".join(parts)
    return str(content)


class Filter:
    class Valves(BaseModel):
        priority: int = Field(default=0)
        AUTO_APPEND: bool = Field(default=True)
        LANGUAGE: str = Field(default="auto", description="auto | en | ru")

    def __init__(self) -> None:
        self.valves = self.Valves()

    async def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        if not self.valves.AUTO_APPEND:
            return body
        messages = body.get("messages") or []
        for i in range(len(messages) - 1, -1, -1):
            msg = messages[i]
            if msg.get("role") != "assistant":
                continue
            content = _message_text(msg.get("content"))
            looks_like_report = bool(
                re.search(
                    r"\|\s*(Severity|Критичность)\s*\|\s*(Status|Статус)",
                    content,
                    re.I,
                )
                or re.search(
                    r"##\s+(Summary table|Сводная таблица)",
                    content,
                    re.I,
                )
                or re.search(r"^\|\s*REQ-\d+\s*\|", content, re.I | re.M)
            )
            if not looks_like_report:
                continue
            if "CIS compliance visualization" in content or "Визуализация соответствия CIS" in content:
                break
            if "data:image/svg+xml;base64," in content and "compliance" in content.lower():
                break
            lang = self.valves.LANGUAGE
            if lang in {"", "auto"}:
                lang = "ru" if re.search(r"[А-Яа-яЁё]", content) else "en"
            chart = build_visualization(content, language=lang)
            if chart:
                msg["content"] = content.rstrip() + "\n\n" + chart
                messages[i] = msg
                body["messages"] = messages
            break
        return body

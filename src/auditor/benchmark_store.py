"""Cumulative audit benchmark ledger (``memory/benchmark.md``).

This module maintains an **append-only history** of completed checklist audits:
status counts and compliance percent per framework. It stores **aggregates only**
— never observations, recommendations, tool output, or credentials.

Pipeline role:
    After finalize or report update, findings are summarized via
    :func:`findings_to_benchmark_metrics` and appended to a JSONL ledger.
    Markdown ``benchmark.md`` is regenerated for operator visibility.

Key entry points:
    :class:`BenchmarkStore` — append entries and rewrite Markdown.
    :func:`findings_to_benchmark_metrics` — derive counts and compliance %.
    :class:`BenchmarkEntry` — one row in the history table.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from auditor.compliance import FindingRow, overall_compliance
from auditor.state import Finding, aggregate_findings

logger = logging.getLogger(__name__)

_HEADER = """# Audit benchmark history

Cumulative scores from completed checklist audits.
Aggregates only (no observations, recommendations, or secrets).

## Latest by framework

{latest_table}

## Full history

| finished_at (UTC) | run_id | framework | pass | fail | partial | error | skipped | assessed | compliance_% | evidence |
|---|---|---|---|---|---|---|---|---|---|---|
"""


@dataclass(frozen=True, slots=True)
class BenchmarkEntry:
    """One completed framework audit row in the benchmark ledger.

    Attributes:
        finished_at: UTC ISO timestamp when the audit was recorded.
        run_id: Evidence run folder id.
        framework_id: Framework key (may include host prefix).
        pass_count: Number of requirements with status ``pass``.
        fail_count: Number of requirements with status ``fail``.
        partial_count: Number of requirements with status ``partial``.
        error_count: Number of requirements with status ``error``.
        skipped_count: Number of requirements marked skipped.
        assessed: Total requirements assessed (excluding skipped).
        compliance_pct: Overall compliance percentage from :mod:`auditor.compliance`.
        evidence: Relative path to evidence folder (optional).
    """

    finished_at: str
    run_id: str
    framework_id: str
    pass_count: int
    fail_count: int
    partial_count: int
    error_count: int
    skipped_count: int
    assessed: int
    compliance_pct: float
    evidence: str

    def to_row(self) -> str:
        """Format this entry as a Markdown table row for the history section.

        Returns:
            Pipe-delimited table row string.
        """
        return (
            f"| {self.finished_at} | `{self.run_id}` | `{self.framework_id}` | "
            f"{self.pass_count} | {self.fail_count} | {self.partial_count} | "
            f"{self.error_count} | {self.skipped_count} | {self.assessed} | "
            f"{self.compliance_pct:.1f} | `{self.evidence}` |"
        )


def _utc_now() -> str:
    """Return current UTC time as ISO string with ``Z`` suffix (no microseconds).

    Returns:
        Timestamp string suitable for benchmark table columns.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def findings_to_benchmark_metrics(
    findings: Mapping[str, Finding],
) -> dict[str, Any]:
    """Derive status counts + overall compliance % from filled findings.

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


class BenchmarkStore:
    """Persist and rewrite ``benchmark.md`` (+ companion JSONL) under memory.

    Attributes:
        path: Path to ``benchmark.md``.
        jsonl_path: Append-only JSONL source of truth (``benchmark.jsonl``).
    """

    def __init__(self, path: Path | str) -> None:
        """Initialize store for a benchmark Markdown file.

        Args:
            path: Target ``benchmark.md`` path; ``.jsonl`` sibling is derived.
        """
        self.path = Path(path)
        self.jsonl_path = self.path.with_suffix(".jsonl")
        self._lock = threading.Lock()

    def append_from_findings(
        self,
        *,
        run_id: str,
        framework_id: str,
        findings: Mapping[str, Finding],
        evidence_relpath: str = "",
    ) -> BenchmarkEntry | None:
        """Append one framework audit row from findings.

        Returns:
            The written entry, or ``None`` when there is nothing to record.
        """
        if not findings or not framework_id:
            return None
        metrics = findings_to_benchmark_metrics(findings)
        entry = BenchmarkEntry(
            finished_at=_utc_now(),
            run_id=run_id or "unknown",
            framework_id=framework_id,
            pass_count=int(metrics["pass"]),
            fail_count=int(metrics["fail"]),
            partial_count=int(metrics["partial"]),
            error_count=int(metrics["error"]),
            skipped_count=int(metrics["skipped"]),
            assessed=int(metrics["assessed"]),
            compliance_pct=float(metrics["compliance_pct"]),
            evidence=evidence_relpath or "",
        )
        self.append(entry)
        return entry

    def append(self, entry: BenchmarkEntry) -> None:
        """Append ``entry`` to JSONL and regenerate Markdown.

        Thread-safe via internal lock.

        Args:
            entry: Completed audit metrics row to persist.
        """
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
            self._rewrite_markdown(self._load_entries())

    def _load_entries(self) -> list[BenchmarkEntry]:
        """Load all benchmark entries from the JSONL file.

        Returns:
            List of entries in file order; empty when file is missing.
        """
        if not self.jsonl_path.is_file():
            return []
        entries: list[BenchmarkEntry] = []
        try:
            for line in self.jsonl_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                entries.append(
                    BenchmarkEntry(
                        finished_at=str(raw.get("finished_at") or ""),
                        run_id=str(raw.get("run_id") or ""),
                        framework_id=str(raw.get("framework_id") or ""),
                        pass_count=int(raw.get("pass_count") or 0),
                        fail_count=int(raw.get("fail_count") or 0),
                        partial_count=int(raw.get("partial_count") or 0),
                        error_count=int(raw.get("error_count") or 0),
                        skipped_count=int(raw.get("skipped_count") or 0),
                        assessed=int(raw.get("assessed") or 0),
                        compliance_pct=float(raw.get("compliance_pct") or 0.0),
                        evidence=str(raw.get("evidence") or ""),
                    )
                )
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            logger.warning("Failed reading benchmark JSONL %s: %s", self.jsonl_path, exc)
        return entries

    def _latest_by_framework(self, entries: list[BenchmarkEntry]) -> list[BenchmarkEntry]:
        """Return the most recent entry per ``framework_id``.

        Args:
            entries: Full history (chronological order).

        Returns:
            Latest entry per framework, sorted by framework id.
        """
        latest: dict[str, BenchmarkEntry] = {}
        for entry in entries:
            latest[entry.framework_id] = entry
        return [latest[k] for k in sorted(latest)]

    def _rewrite_markdown(self, entries: list[BenchmarkEntry]) -> None:
        """Regenerate ``benchmark.md`` from the full entry list.

        Args:
            entries: All benchmark rows (newest history section uses reverse order).
        """
        latest = self._latest_by_framework(entries)
        if latest:
            latest_lines = [
                "| framework | finished_at (UTC) | run_id | compliance_% | pass | fail | partial | error | skipped |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
            for e in latest:
                latest_lines.append(
                    f"| `{e.framework_id}` | {e.finished_at} | `{e.run_id}` | "
                    f"{e.compliance_pct:.1f} | {e.pass_count} | {e.fail_count} | "
                    f"{e.partial_count} | {e.error_count} | {e.skipped_count} |"
                )
            latest_table = "\n".join(latest_lines)
        else:
            latest_table = "_No audits recorded yet._"

        history_rows = [e.to_row() for e in reversed(entries)]  # newest first
        body = _HEADER.format(latest_table=latest_table)
        if history_rows:
            body = body + "\n".join(history_rows) + "\n"
        else:
            body = body + "\n_No history yet._\n"
        self.path.write_text(body, encoding="utf-8")

    def ensure_file(self) -> None:
        """Create an empty ledger Markdown file if missing.

        Writes placeholder tables when no audits have been recorded yet.
        """
        with self._lock:
            if self.path.is_file():
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rewrite_markdown([])

"""Persist per-requirement command execution artifacts on disk.

Every audit run creates::

    <EVIDENCE_DIR>/<run_id>/
      meta.json
      report.md                  (written at finalize when available)
      <framework_id>/
        REQ-001/
          requirement.json
          001_ssh_run.txt
          002_mcp_query.txt
          finding.json
        REQ-002/
          ...

Tool outputs written here are **full** (not truncated for the LLM context).
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def new_run_id() -> str:
    """Return a filesystem-safe run id: ``YYYYMMDDTHHMMSSZ_<shortuuid>``."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid4().hex[:8]}"


def _safe_segment(value: str, fallback: str = "unknown") -> str:
    cleaned = _SAFE.sub("_", (value or "").strip()).strip("._-")
    return cleaned or fallback


class EvidenceStore:
    """Create run / requirement folders and write command results."""

    def __init__(self, root: Path | str, run_id: str | None = None) -> None:
        self.run_id = run_id or new_run_id()
        self.root = Path(root) / self.run_id
        self.root.mkdir(parents=True, exist_ok=True)
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    def write_run_meta(self, **meta: Any) -> Path:
        """Write/merge ``meta.json`` at the run root."""
        path = self.root / "meta.json"
        existing: dict[str, Any] = {}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except json.JSONDecodeError:
                existing = {}
        existing.update(meta)
        existing.setdefault("run_id", self.run_id)
        existing.setdefault(
            "updated_at",
            datetime.now(timezone.utc).isoformat(),
        )
        path.write_text(
            json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path

    def requirement_dir(self, framework_id: str, req_id: str) -> Path:
        """Return (and create) the folder for one requirement."""
        path = (
            self.root
            / _safe_segment(framework_id, "framework")
            / _safe_segment(req_id, "REQ")
        )
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_requirement(
        self,
        framework_id: str,
        req_id: str,
        payload: dict[str, Any],
    ) -> Path:
        """Write the checklist requirement snapshot for the folder."""
        path = self.requirement_dir(framework_id, req_id) / "requirement.json"
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path

    def write_tool_result(
        self,
        framework_id: str,
        req_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        result: str,
        *,
        error: str | None = None,
    ) -> Path:
        """Append one command/tool execution result under the requirement folder.

        Files are named ``NNN_<tool>.txt`` with a human-readable header plus
        the full stdout/result body.
        """
        req_dir = self.requirement_dir(framework_id, req_id)
        key = f"{framework_id}/{req_id}"
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + 1
            seq = self._counters[key]

        safe_tool = _safe_segment(tool_name or "tool", "tool")
        path = req_dir / f"{seq:03d}_{safe_tool}.txt"

        # Also keep a machine-readable sidecar for the same step.
        json_path = req_dir / f"{seq:03d}_{safe_tool}.json"
        record = {
            "seq": seq,
            "tool": tool_name,
            "arguments": arguments or {},
            "error": error,
            "result": result,
            "written_at": datetime.now(timezone.utc).isoformat(),
        }
        json_path.write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        lines = [
            f"tool: {tool_name}",
            f"seq: {seq}",
            f"written_at: {record['written_at']}",
            "arguments:",
            json.dumps(arguments or {}, indent=2, ensure_ascii=False),
        ]
        if error:
            lines.extend(["error:", error])
        lines.extend(["", "result:", result if result.endswith("\n") else result + "\n"])
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def write_finding(
        self,
        framework_id: str,
        req_id: str,
        finding: dict[str, Any],
    ) -> Path:
        """Write the filled finding cells for the requirement."""
        path = self.requirement_dir(framework_id, req_id) / "finding.json"
        path.write_text(
            json.dumps(finding, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path

    def write_report(self, framework_id: str, report: str) -> Path:
        """Write the finalized Markdown report under the framework folder."""
        fw_dir = self.root / _safe_segment(framework_id, "framework")
        fw_dir.mkdir(parents=True, exist_ok=True)
        path = fw_dir / "report.md"
        path.write_text(report if report.endswith("\n") else report + "\n", encoding="utf-8")
        # Also copy to run root for single-framework convenience.
        (self.root / "report.md").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        return path

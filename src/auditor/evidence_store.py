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
_SEQ_FILE = re.compile(r"^(\d{3})_.+\.(txt|json)$", re.IGNORECASE)


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
        self.seed_counters_from_disk()

    @classmethod
    def open_existing(cls, evidence_dir: Path | str, run_id: str) -> EvidenceStore:
        """Open an existing run folder (does not create a new run id)."""
        base = Path(evidence_dir)
        path = base / run_id
        if not path.is_dir():
            raise FileNotFoundError(f"Evidence run not found: {path}")
        store = cls(base, run_id=run_id)
        return store

    def seed_counters_from_disk(self) -> None:
        """Initialize tool sequence counters from existing ``NNN_*.txt`` files.

        Required when reopening a finished audit so follow-up commands append
        (``003_…``) instead of overwriting ``001_…``.
        """
        if not self.root.is_dir():
            return
        with self._lock:
            for fw_dir in self.root.iterdir():
                if not fw_dir.is_dir() or fw_dir.name.startswith("."):
                    continue
                # Skip non-framework files (meta/report live at root).
                for req_dir in fw_dir.iterdir():
                    if not req_dir.is_dir():
                        continue
                    max_seq = 0
                    for path in req_dir.iterdir():
                        match = _SEQ_FILE.match(path.name)
                        if match:
                            max_seq = max(max_seq, int(match.group(1)))
                    if max_seq:
                        key = f"{fw_dir.name}/{req_dir.name}"
                        self._counters[key] = max(
                            self._counters.get(key, 0), max_seq
                        )

    def read_run_meta(self) -> dict[str, Any]:
        """Load ``meta.json`` or return an empty dict."""
        path = self.root / "meta.json"
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def list_framework_ids(self) -> list[str]:
        """Return framework folder names under this run (non-hidden dirs)."""
        if not self.root.is_dir():
            return []
        skip = {"__pycache__"}
        out: list[str] = []
        for path in sorted(self.root.iterdir()):
            if path.is_dir() and path.name not in skip and not path.name.startswith("."):
                # Framework folders contain REQ-* or report.md
                if (path / "report.md").is_file() or any(
                    p.is_dir() and p.name.upper().startswith("REQ")
                    for p in path.iterdir()
                ):
                    out.append(path.name)
        return out

    def list_requirement_ids(self, framework_id: str) -> list[str]:
        """Return REQ folder names for a framework."""
        fw_dir = self.root / _safe_segment(framework_id, "framework")
        if not fw_dir.is_dir():
            return []
        return sorted(
            p.name
            for p in fw_dir.iterdir()
            if p.is_dir() and p.name.upper().startswith("REQ")
        )

    def load_finding(self, framework_id: str, req_id: str) -> dict[str, Any] | None:
        """Load ``finding.json`` for a requirement, if present."""
        path = (
            self.root
            / _safe_segment(framework_id, "framework")
            / _safe_segment(req_id, "REQ")
            / "finding.json"
        )
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def load_findings(self, framework_id: str) -> dict[str, dict[str, Any]]:
        """Load all findings for a framework keyed by REQ id."""
        out: dict[str, dict[str, Any]] = {}
        for req_id in self.list_requirement_ids(framework_id):
            finding = self.load_finding(framework_id, req_id)
            if finding is not None:
                out[req_id] = finding
        return out

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
        existing["run_id"] = self.run_id
        existing["updated_at"] = datetime.now(timezone.utc).isoformat()
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

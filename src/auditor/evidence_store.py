"""Persist per-requirement command execution artifacts on disk.

Every audit run creates::

    <EVIDENCE_DIR>/<client_name>/
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

After intake, the run folder is named after the **client** (not a timestamp).
Tool outputs written here are **full** (not truncated for the LLM context).
"""

from __future__ import annotations

import json
import re
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from auditor.tools.secrets import redact_secrets

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_SEQ_FILE = re.compile(r"^(\d{3})_.+\.(txt|json)$", re.IGNORECASE)


def new_run_id() -> str:
    """Return a temporary filesystem-safe run id (renamed to client name after intake)."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid4().hex[:8]}"


def client_artifacts_id(client_name: str) -> str:
    """Filesystem-safe artifacts folder name from a client display name."""
    return _safe_segment(client_name, "client")


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
        # Optional host slug for multi-host layout: ``<root>/<host>/<framework>/…``
        self.host_segment: str | None = None
        self.seed_counters_from_disk()

    def host_root(self, host_id: str | None = None) -> Path:
        """Return evidence root for a host (or run root when no host)."""
        segment = host_id if host_id is not None else self.host_segment
        if segment:
            path = self.root / _safe_segment(segment, "host")
            path.mkdir(parents=True, exist_ok=True)
            return path
        return self.root

    def _framework_root(self, framework_id: str, host_id: str | None = None) -> Path:
        parts = [p for p in str(framework_id).replace("\\", "/").split("/") if p]
        # Explicit ``host/framework`` key (no active host_segment)
        if (
            len(parts) >= 2
            and host_id is None
            and not self.host_segment
        ):
            return self.root.joinpath(*[_safe_segment(p, "x") for p in parts])
        base = self.host_root(host_id)
        fw = parts[-1] if parts else "framework"
        return base / _safe_segment(fw, "framework")

    def rebind_run_id(self, new_run_id: str) -> str:
        """Rename this run folder to ``new_run_id`` (typically the client name).

        If the target folder already exists, merges contents into it and removes
        the temporary source folder.
        """
        new_id = _safe_segment(new_run_id, "client")
        base = self.root.parent
        new_root = base / new_id
        old_root = self.root
        if new_root.resolve() == old_root.resolve():
            self.run_id = new_id
            return self.run_id

        new_root.mkdir(parents=True, exist_ok=True)
        if old_root.is_dir():
            for item in old_root.iterdir():
                dest = new_root / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.copytree(item, dest, dirs_exist_ok=True)
                        shutil.rmtree(item)
                    else:
                        item.rename(dest)
                else:
                    shutil.copy2(item, dest)
                    item.unlink(missing_ok=True)
            try:
                old_root.rmdir()
            except OSError:
                shutil.rmtree(old_root, ignore_errors=True)

        self.run_id = new_id
        self.root = new_root
        self.seed_counters_from_disk()
        return self.run_id

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

        def _scan_fw_dir(fw_dir: Path, prefix: str = "") -> None:
            for req_dir in fw_dir.iterdir():
                if not req_dir.is_dir():
                    continue
                max_seq = 0
                for path in req_dir.iterdir():
                    match = _SEQ_FILE.match(path.name)
                    if match:
                        max_seq = max(max_seq, int(match.group(1)))
                if max_seq:
                    key = f"{prefix}{fw_dir.name}/{req_dir.name}"
                    self._counters[key] = max(self._counters.get(key, 0), max_seq)

        with self._lock:
            for child in self.root.iterdir():
                if not child.is_dir() or child.name.startswith("."):
                    continue
                # Framework at run root (legacy single-host)
                if (child / "report.md").is_file() or any(
                    p.is_dir() and p.name.upper().startswith("REQ")
                    for p in child.iterdir()
                    if p.is_dir()
                ):
                    _scan_fw_dir(child)
                    continue
                # Host folder containing framework children
                for fw_dir in child.iterdir():
                    if not fw_dir.is_dir() or fw_dir.name.startswith("."):
                        continue
                    if (fw_dir / "report.md").is_file() or any(
                        p.is_dir() and p.name.upper().startswith("REQ")
                        for p in fw_dir.iterdir()
                        if p.is_dir()
                    ):
                        _scan_fw_dir(fw_dir, prefix=f"{child.name}/")

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
        """Return framework folder names (``fw`` or ``host/fw``)."""
        if not self.root.is_dir():
            return []
        skip = {"__pycache__"}
        out: list[str] = []

        def _is_fw(path: Path) -> bool:
            if not path.is_dir() or path.name in skip or path.name.startswith("."):
                return False
            if (path / "report.md").is_file():
                return True
            try:
                return any(
                    p.is_dir() and p.name.upper().startswith("REQ") for p in path.iterdir()
                )
            except OSError:
                return False

        for path in sorted(self.root.iterdir()):
            if not path.is_dir() or path.name in skip or path.name.startswith("."):
                continue
            if _is_fw(path):
                out.append(path.name)
                continue
            for child in sorted(path.iterdir()):
                if _is_fw(child):
                    out.append(f"{path.name}/{child.name}")
        return out

    def list_requirement_ids(self, framework_id: str) -> list[str]:
        """Return REQ folder names for a framework."""
        fw_dir = self._framework_root(framework_id)
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
            self._framework_root(framework_id)
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
        path = self._framework_root(framework_id) / _safe_segment(req_id, "REQ")
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
        host = self.host_segment or ""
        key = f"{host}/{framework_id}/{req_id}" if host else f"{framework_id}/{req_id}"
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + 1
            seq = self._counters[key]

        safe_tool = _safe_segment(tool_name or "tool", "tool")
        path = req_dir / f"{seq:03d}_{safe_tool}.txt"
        safe_args = redact_secrets(arguments or {})

        # Also keep a machine-readable sidecar for the same step.
        json_path = req_dir / f"{seq:03d}_{safe_tool}.json"
        record = {
            "seq": seq,
            "tool": tool_name,
            "arguments": safe_args,
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
            json.dumps(safe_args, indent=2, ensure_ascii=False),
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

    def list_tool_result_files(self, framework_id: str, req_id: str) -> list[Path]:
        """Return ordered ``NNN_<tool>.txt`` evidence files for a requirement."""
        req_dir = self._framework_root(framework_id) / _safe_segment(req_id, "REQ")
        if not req_dir.is_dir():
            return []
        files = [
            p
            for p in req_dir.iterdir()
            if p.is_file()
            and p.suffix == ".txt"
            and re.match(r"^\d{3}_", p.name)
        ]
        return sorted(files, key=lambda p: p.name)

    def load_evidence_text(
        self,
        framework_id: str,
        req_id: str,
        *,
        max_chars: int = 12000,
    ) -> str:
        """Concatenate stored tool logs for refill / observation updates."""
        chunks: list[str] = []
        total = 0
        for path in self.list_tool_result_files(framework_id, req_id):
            try:
                body = path.read_text(encoding="utf-8")
            except OSError:
                continue
            piece = f"### {path.name}\n{body.strip()}"
            if total + len(piece) > max_chars:
                remain = max_chars - total
                if remain > 80:
                    chunks.append(piece[:remain] + "\n…(truncated)")
                break
            chunks.append(piece)
            total += len(piece) + 2
        return "\n\n".join(chunks).strip()

    def write_report(self, framework_id: str, report: str) -> Path:
        """Write the finalized Markdown report under the framework folder.

        Does **not** overwrite the run-root ``report.md`` — multi-framework
        merges (or a single-framework publish step) own that file.
        """
        fw_dir = self._framework_root(framework_id)
        fw_dir.mkdir(parents=True, exist_ok=True)
        path = fw_dir / "report.md"
        path.write_text(report if report.endswith("\n") else report + "\n", encoding="utf-8")
        return path

    def write_root_report(self, report: str) -> Path:
        """Write the combined (or single-framework) report at the run root."""
        path = self.root / "report.md"
        path.write_text(report if report.endswith("\n") else report + "\n", encoding="utf-8")
        return path

    def framework_report_paths(self) -> list[Path]:
        """Return existing ``…/report.md`` files (root frameworks or host/fw)."""
        if not self.root.is_dir():
            return []
        out: list[Path] = []
        for child in sorted(self.root.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            report = child / "report.md"
            if report.is_file():
                out.append(report)
                continue
            for grandchild in sorted(child.iterdir()):
                if not grandchild.is_dir() or grandchild.name.startswith("."):
                    continue
                nested = grandchild / "report.md"
                if nested.is_file():
                    out.append(nested)
        return out

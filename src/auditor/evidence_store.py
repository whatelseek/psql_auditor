"""Persist per-requirement command execution artifacts on disk.

This module implements the **on-disk evidence layer** for every audit run.
Tool stdout, requirement snapshots, filled findings, and reports are written
under a hierarchical folder layout keyed by run id, framework, and REQ id.

Pipeline role:
    :class:`EvidenceStore` is the single write path for checklist audits,
    ad-hoc commands, and follow-up evidence. The graph, follow-up handlers,
    and report rebuild logic all read/write through this API.

Layout (after intake, run folder is typically the **client name**)::

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

Tool outputs written here are **full** (not truncated for the LLM context).

Key entry points:
    :func:`new_run_id` — allocate a temporary run folder name.
    :class:`EvidenceStore` — create/open runs, write tool results and findings.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from auditor.tools.secrets import redact_secrets

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_SEQ_FILE = re.compile(r"^(\d{3})_.+\.(txt|json)$", re.IGNORECASE)

# Per-task host slug so parallel host/framework jobs share one EvidenceStore
# without racing on the mutable ``host_segment`` attribute.
_active_host_segment: ContextVar[str | None] = ContextVar(
    "evidence_host_segment", default=None
)


@contextmanager
def bind_host_segment(host_id: str | None) -> Iterator[str | None]:
    """Bind the active multi-host evidence slug for the current async context.

    Args:
        host_id: Host slug (or empty/None to clear for this scope).

    Yields:
        Normalized host slug, or ``None``.
    """
    segment = (host_id or "").strip() or None
    token = _active_host_segment.set(segment)
    try:
        yield segment
    finally:
        _active_host_segment.reset(token)


def effective_host_segment(store_segment: str | None = None) -> str | None:
    """Return ContextVar host slug, falling back to a store attribute.

    Args:
        store_segment: Optional :attr:`EvidenceStore.host_segment` fallback.

    Returns:
        Active host slug, or ``None``.
    """
    bound = _active_host_segment.get()
    if bound:
        return bound
    return (store_segment or "").strip() or None


def new_run_id() -> str:
    """Return a temporary filesystem-safe run id (renamed to client name after intake).

    Format: ``YYYYMMDDTHHMMSSZ_<8-hex>`` UTC timestamp plus short uuid suffix.

    Returns:
        New run id string suitable as an evidence folder name.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid4().hex[:8]}"


def client_artifacts_id(client_name: str) -> str:
    """Derive filesystem-safe artifacts folder name from a client display name.

    Args:
        client_name: Human-readable client or organization name.

    Returns:
        Sanitized lowercase slug (falls back to ``"client"``).
    """
    return _safe_segment(client_name, "client")


def _safe_segment(value: str, fallback: str = "unknown") -> str:
    """Sanitize a path segment for evidence folder names.

    Args:
        value: Raw segment (framework id, REQ id, host slug).
        fallback: Value when cleaning yields empty string.

    Returns:
        Alphanumeric/``._-`` only segment safe for filesystem paths.
    """
    cleaned = _SAFE.sub("_", (value or "").strip()).strip("._-")
    return cleaned or fallback


class EvidenceStore:
    """Create run / requirement folders and write command results.

    Thread-safe for concurrent tool writes within one run via an internal lock
    and per-requirement sequence counters for ``NNN_<tool>.txt`` filenames.

    Attributes:
        run_id: Current run folder name (may be renamed via :meth:`rebind_run_id`).
        root: Absolute path to ``<evidence_dir>/<run_id>/``.
        host_segment: Optional active host slug for multi-host layout.
    """

    def __init__(self, root: Path | str, run_id: str | None = None) -> None:
        """Initialize store and create the run directory if needed.

        Args:
            root: Evidence root directory (parent of run folders).
            run_id: Existing or new run id; generated when omitted.
        """
        self.run_id = run_id or new_run_id()
        self.root = Path(root) / self.run_id
        self.root.mkdir(parents=True, exist_ok=True)
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()
        # Optional host slug for multi-host layout: ``<root>/<host>/<framework>/…``
        self.host_segment: str | None = None
        self.seed_counters_from_disk()

    def host_root(self, host_id: str | None = None) -> Path:
        """Return evidence root for a host (or run root when no host).

        Args:
            host_id: Explicit host slug; defaults to :attr:`host_segment`.

        Returns:
            ``<run_root>/<host>/`` when a host is set, else ``<run_root>``.
        """
        if host_id is not None:
            segment = (host_id or "").strip() or None
        else:
            segment = effective_host_segment(self.host_segment)
        if segment:
            path = self.root / _safe_segment(segment, "host")
            path.mkdir(parents=True, exist_ok=True)
            return path
        return self.root

    def _framework_root(self, framework_id: str, host_id: str | None = None) -> Path:
        """Resolve directory for a framework key (supports ``host/fw`` paths).

        Args:
            framework_id: Bare or composite framework key.
            host_id: Optional host override for multi-host layout.

        Returns:
            Path to framework directory under the run (created on write).
        """
        parts = [p for p in str(framework_id).replace("\\", "/").split("/") if p]
        active = (
            (host_id or "").strip() or None
            if host_id is not None
            else effective_host_segment(self.host_segment)
        )
        # Explicit ``host/framework`` key (no active host_segment)
        if len(parts) >= 2 and host_id is None and not active:
            return self.root.joinpath(*[_safe_segment(p, "x") for p in parts])
        base = self.host_root(host_id)
        fw = parts[-1] if parts else "framework"
        return base / _safe_segment(fw, "framework")

    def rebind_run_id(self, new_run_id: str) -> str:
        """Rename this run folder to ``new_run_id`` (typically the client name).

        If the target folder already exists, merges contents into it and removes
        the temporary source folder.

        Args:
            new_run_id: Desired folder name (sanitized).

        Returns:
            Final sanitized ``run_id`` after rename/merge.
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
        """Open an existing run folder (does not create a new run id).

        Args:
            evidence_dir: Root evidence directory.
            run_id: Existing run folder name.

        Returns:
            Store instance with counters seeded from on-disk tool files.

        Raises:
            FileNotFoundError: When ``<evidence_dir>/<run_id>`` does not exist.
        """
        base = Path(evidence_dir)
        path = base / run_id
        if not path.is_dir():
            raise FileNotFoundError(f"Evidence run not found: {path}")
        store = cls(base, run_id=run_id)
        return store

    def seed_counters_from_disk(self) -> None:
        """Initialize tool sequence counters from existing ``NNN_*.txt`` files.

        Required when reopening a finished audit so follow-up commands append
        (``003_…``) instead of overwriting ``001_…``. Scans both legacy
        single-host and ``host/framework`` nested layouts.
        """
        if not self.root.is_dir():
            return

        def _scan_fw_dir(fw_dir: Path, prefix: str = "") -> None:
            """Update ``_counters`` from the highest numbered evidence files under ``fw_dir``.

            Args:
                fw_dir: Framework evidence directory containing REQ-* subfolders.
                prefix: Optional ``host/`` prefix for nested multi-host layouts.
            """
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
        """Load ``meta.json`` or return an empty dict.

        Returns:
            Parsed meta dict, or ``{}`` when missing or invalid.
        """
        path = self.root / "meta.json"
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def list_framework_ids(self) -> list[str]:
        """Return framework folder names (``fw`` or ``host/fw``).

        Detects framework directories by presence of ``report.md`` or REQ-* subfolders.

        Returns:
            Sorted list of evidence framework keys under this run.
        """
        if not self.root.is_dir():
            return []
        skip = {"__pycache__"}
        out: list[str] = []

        def _is_fw(path: Path) -> bool:
            """Return True when ``path`` looks like a framework evidence folder.

            A framework folder contains ``report.md`` and/or REQ-* requirement
            subdirectories.

            Args:
                path: Candidate directory under the run root or a host folder.
            """
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
        """Return REQ folder names for a framework.

        Args:
            framework_id: Evidence framework key.

        Returns:
            Sorted list of requirement ids (e.g. ``REQ-001``).
        """
        fw_dir = self._framework_root(framework_id)
        if not fw_dir.is_dir():
            return []
        return sorted(
            p.name
            for p in fw_dir.iterdir()
            if p.is_dir() and p.name.upper().startswith("REQ")
        )

    def load_finding(self, framework_id: str, req_id: str) -> dict[str, Any] | None:
        """Load ``finding.json`` for a requirement, if present.

        Args:
            framework_id: Evidence framework key.
            req_id: Requirement id.

        Returns:
            Parsed finding dict, or ``None`` when missing or invalid.
        """
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
        """Load all findings for a framework keyed by ``result_id``.

        Falls back to ``requirement_id`` only when legacy finding.json lacks
        ``result_id`` (pre-CORE-003). Folder layout remains REQ-based.

        Args:
            framework_id: Evidence framework key.

        Returns:
            Dict mapping ``result_id`` (preferred) to finding payload.
        """
        out: dict[str, dict[str, Any]] = {}
        for req_id in self.list_requirement_ids(framework_id):
            finding = self.load_finding(framework_id, req_id)
            if finding is None:
                continue
            key = str(finding.get("result_id") or "").strip() or req_id
            out[key] = finding
        return out

    def load_finding_requirement_ids(self, framework_id: str) -> set[str]:
        """Return requirement_ids that have a finding.json on disk."""
        out: set[str] = set()
        for req_id in self.list_requirement_ids(framework_id):
            if self.load_finding(framework_id, req_id) is not None:
                out.add(req_id)
        return out

    def write_run_meta(self, **meta: Any) -> Path:
        """Write/merge ``meta.json`` at the run root.

        Merges with existing keys, sets ``run_id`` and ``updated_at`` UTC.

        Args:
            **meta: Arbitrary metadata fields (client, frameworks, language, …).

        Returns:
            Path to written ``meta.json``.
        """
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
        """Return (and create) the folder for one requirement.

        Args:
            framework_id: Evidence framework key.
            req_id: Requirement id.

        Returns:
            Path to ``<framework>/<req_id>/`` directory.
        """
        path = self._framework_root(framework_id) / _safe_segment(req_id, "REQ")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_requirement(
        self,
        framework_id: str,
        req_id: str,
        payload: dict[str, Any],
    ) -> Path:
        """Write the checklist requirement snapshot for the folder.

        Args:
            framework_id: Evidence framework key.
            req_id: Requirement id.
            payload: Checklist fields (id, title, severity, pass_criteria, …).

        Returns:
            Path to ``requirement.json``.
        """
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
        the full stdout/result body. A JSON sidecar is written alongside.

        Args:
            framework_id: Evidence framework key.
            req_id: Requirement id.
            tool_name: Tool identifier (e.g. ``ssh_run``).
            arguments: Tool call arguments (secrets redacted).
            result: Full tool output text.
            error: Optional error message when the call failed.

        Returns:
            Path to the ``.txt`` evidence file.
        """
        req_dir = self.requirement_dir(framework_id, req_id)
        host = effective_host_segment(self.host_segment) or ""
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
        """Write the filled finding cells for the requirement.

        Args:
            framework_id: Evidence framework key.
            req_id: Requirement id.
            finding: Status, observation, recommendation, and metadata.

        Returns:
            Path to ``finding.json``.
        """
        path = self.requirement_dir(framework_id, req_id) / "finding.json"
        path.write_text(
            json.dumps(finding, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path

    def list_tool_result_files(self, framework_id: str, req_id: str) -> list[Path]:
        """Return ordered ``NNN_<tool>.txt`` evidence files for a requirement.

        Args:
            framework_id: Evidence framework key.
            req_id: Requirement id.

        Returns:
            Sorted list of ``.txt`` tool log paths (empty when folder missing).
        """
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
        """Concatenate stored tool logs for refill / observation updates.

        Args:
            framework_id: Evidence framework key.
            req_id: Requirement id.
            max_chars: Maximum total characters (truncates last file with ellipsis).

        Returns:
            Markdown-ish concatenation of tool log bodies.
        """
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

        Args:
            framework_id: Evidence framework key.
            report: Full Markdown report body.

        Returns:
            Path to ``<framework>/report.md``.
        """
        fw_dir = self._framework_root(framework_id)
        fw_dir.mkdir(parents=True, exist_ok=True)
        path = fw_dir / "report.md"
        path.write_text(report if report.endswith("\n") else report + "\n", encoding="utf-8")
        return path

    def write_root_report(self, report: str) -> Path:
        """Write the combined (or single-framework) report at the run root.

        Also writes ``report.docx`` and ``report.xlsx`` beside ``report.md``
        when export libraries are available.

        Args:
            report: Full Markdown report (possibly multi-framework merge).

        Returns:
            Path to ``<run_root>/report.md``.
        """
        path = self.root / "report.md"
        path.write_text(report if report.endswith("\n") else report + "\n", encoding="utf-8")
        try:
            from auditor.report_exports import write_report_exports

            write_report_exports(self.root, report)
        except Exception:  # noqa: BLE001
            pass
        return path

    def framework_report_paths(self) -> list[Path]:
        """Return existing ``…/report.md`` files (root frameworks or host/fw).

        Returns:
            Sorted list of per-framework report paths under this run.
        """
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

"""Persist multi-framework session queue across agent restarts.

This module stores **in-progress audit session state** on disk so LangGraph
checkpoints can be resumed after process restarts. Multi-host / multi-framework
job queues and SSH target descriptors are written to ``session.json`` under
each evidence run (passwords retained for trusted resume contexts).

Pipeline role:
    Used by the graph during long audits to persist ``remaining_jobs``,
    track interrupted runs in ``meta.json``, and support ``continue`` commands
    coordinated with :mod:`auditor.results_store`.

Key entry points:
    :func:`save_multi_session` / :func:`load_all_multi_sessions` — per-thread session blobs.
    :func:`write_run_status` — update run meta status and pending REQ ids.
    :func:`find_interrupted_run` — locate newest interrupted evidence run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def session_path(evidence_dir: Path, run_id: str) -> Path:
    """Return path to ``session.json`` for an evidence run.

    Args:
        evidence_dir: Root evidence directory.
        run_id: Run folder name.

    Returns:
        ``<evidence_dir>/<run_id>/session.json`` path.
    """
    return Path(evidence_dir) / run_id / "session.json"


def save_multi_session(
    evidence_dir: Path,
    run_id: str,
    thread_id: str,
    session: dict[str, Any],
) -> Path:
    """Write one multi-session entry (SSH secrets stripped where applicable).

    Merges into existing ``session.json`` under ``sessions[thread_id]``.

    Args:
        evidence_dir: Root evidence directory.
        run_id: Evidence run folder name.
        thread_id: LangGraph thread id key.
        session: Serializable session dict (sanitized via :func:`_sanitize_session`).

    Returns:
        Path to written ``session.json``.
    """
    path = session_path(evidence_dir, run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _load(path)
    safe = _sanitize_session(session)
    sessions = payload.get("sessions") if isinstance(payload.get("sessions"), dict) else {}
    sessions[thread_id] = safe
    payload["sessions"] = sessions
    payload["run_id"] = run_id
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def drop_multi_session(evidence_dir: Path, run_id: str, thread_id: str) -> None:
    """Remove one thread's session entry from ``session.json``.

    No-op when the file or thread key does not exist.

    Args:
        evidence_dir: Root evidence directory.
        run_id: Evidence run folder name.
        thread_id: LangGraph thread id to remove.
    """
    path = session_path(evidence_dir, run_id)
    if not path.is_file():
        return
    payload = _load(path)
    sessions = payload.get("sessions")
    if isinstance(sessions, dict) and thread_id in sessions:
        sessions.pop(thread_id, None)
        payload["sessions"] = sessions
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_all_multi_sessions(evidence_dir: Path, run_id: str) -> dict[str, dict[str, Any]]:
    """Load all per-thread session dicts for an evidence run.

    Args:
        evidence_dir: Root evidence directory.
        run_id: Evidence run folder name.

    Returns:
        Mapping of thread id to sanitized session payload.
    """
    path = session_path(evidence_dir, run_id)
    payload = _load(path)
    sessions = payload.get("sessions")
    return dict(sessions) if isinstance(sessions, dict) else {}


def write_run_status(
    evidence_dir: Path,
    run_id: str,
    *,
    status: str,
    thread_id: str = "",
    pending_ids: list[str] | None = None,
    framework_id: str = "",
) -> None:
    """Update run ``meta.json`` with lifecycle status and resume hints.

    Opens the evidence store and merges status, continue thread id, pending
    requirement ids, and current framework id.

    Args:
        evidence_dir: Root evidence directory.
        run_id: Evidence run folder name.
        status: Run status (e.g. ``running``, ``interrupted``, ``completed``).
        thread_id: LangGraph thread id for continue commands.
        pending_ids: Remaining REQ ids in the job queue.
        framework_id: Active framework key when interrupted mid-run.
    """
    from auditor.evidence_store import EvidenceStore

    store = EvidenceStore.open_existing(evidence_dir, run_id)
    meta: dict[str, Any] = {"status": status}
    if thread_id:
        meta["continue_thread_id"] = thread_id
    if framework_id:
        meta["framework_id"] = framework_id
    if pending_ids is not None:
        meta["pending_ids"] = list(pending_ids)
    store.write_run_meta(**meta)


def find_interrupted_run(evidence_dir: Path) -> tuple[str, dict[str, Any]] | None:
    """Return newest interrupted run_id + meta, if any.

    Scans all run folders with ``meta.json`` where ``status == "interrupted"``.

    .. note::

        Do **not** use this to identify the active run for continue/cancel
        (CORE-002). Prefer an explicit ``run_id`` / ``audit_run_id`` or
        :func:`find_run_for_thread`.

    Args:
        evidence_dir: Root evidence directory.

    Returns:
        Tuple of ``(run_id, meta_dict)`` for the newest interrupted run,
        or ``None`` when none found.
    """
    root = Path(evidence_dir)
    if not root.is_dir():
        return None
    candidates: list[tuple[float, str, dict[str, Any]]] = []
    for child in root.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        meta_path = child / "meta.json"
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict):
            continue
        if str(meta.get("status") or "") != "interrupted":
            continue
        mtime = meta_path.stat().st_mtime
        candidates.append((mtime, child.name, meta))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    _, run_id, meta = candidates[0]
    return run_id, meta


def find_run_for_thread(
    evidence_dir: Path, thread_id: str
) -> tuple[str, dict[str, Any]] | None:
    """Locate evidence run whose meta/session is bound to ``thread_id``.

    Explicit thread binding — never falls back to "latest interrupted".
    """
    if not thread_id:
        return None
    root = Path(evidence_dir)
    if not root.is_dir():
        return None
    for child in root.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        meta_path = child / "meta.json"
        meta: dict[str, Any] = {}
        if meta_path.is_file():
            try:
                loaded = json.loads(meta_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    meta = loaded
            except (OSError, json.JSONDecodeError):
                meta = {}
            cont = str(meta.get("continue_thread_id") or "")
            tid = str(meta.get("thread_id") or "")
            # Exact bind, or child job thread under the same base continue id.
            if thread_id == cont or thread_id == tid:
                return child.name, meta
            if cont and thread_id.startswith(f"{cont}:"):
                return child.name, meta
        sessions = load_all_multi_sessions(evidence_dir, child.name)
        if thread_id in sessions:
            return child.name, meta or {"thread_id": thread_id}
    return None


def _sanitize_session(session: dict[str, Any]) -> dict[str, Any]:
    """Drop non-serializable values; normalize SSH target for resume.

    Preserves ``remaining_jobs``, ``completed``, and ``intake_state`` verbatim.
    Serializes ``ssh_target`` to a plain dict (password retained for trusted
    resume inside the secrets volume context).

    Args:
        session: Raw in-memory session dict from the graph.

    Returns:
        JSON-serializable session dict safe for ``session.json``.
    """
    out: dict[str, Any] = {}
    for key, value in session.items():
        if key == "ssh_target":
            # InventorySshTarget or similar — store dict fields without assuming type
            if value is None:
                out[key] = None
            elif hasattr(value, "__dict__"):
                raw = {
                    k: getattr(value, k, None)
                    for k in (
                        "host",
                        "port",
                        "user",
                        "password",
                        "private_key_path",
                        "strict_host_key",
                        "label",
                    )
                }
                # Keep password for resume inside trusted secrets volume context;
                # operators already store it in INVENTORY.md.
                out[key] = raw
            elif isinstance(value, dict):
                out[key] = dict(value)
            else:
                out[key] = str(value)
        elif key in {"remaining_jobs", "completed", "intake_state"}:
            out[key] = value
        else:
            try:
                json.dumps(value)
                out[key] = value
            except TypeError:
                out[key] = str(value)
    return out


def _load(path: Path) -> dict[str, Any]:
    """Load JSON dict from path, returning ``{}`` on missing or invalid files.

    Args:
        path: Path to a JSON file.

    Returns:
        Parsed dict or empty dict.
    """
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}

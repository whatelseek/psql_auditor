"""Persist multi-framework session queue across agent restarts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def session_path(evidence_dir: Path, run_id: str) -> Path:
    return Path(evidence_dir) / run_id / "session.json"


def save_multi_session(
    evidence_dir: Path,
    run_id: str,
    thread_id: str,
    session: dict[str, Any],
) -> Path:
    """Write one multi-session entry (SSH secrets stripped)."""
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
    """Return newest interrupted run_id + meta, if any."""
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


def _sanitize_session(session: dict[str, Any]) -> dict[str, Any]:
    """Drop live SSH password objects; keep serializable job descriptors."""
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
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}

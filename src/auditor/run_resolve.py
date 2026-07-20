"""Resolve prior audit run / framework from chat text, history, or disk."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from auditor.evidence_store import EvidenceStore
from auditor.frameworks import get_framework, route_framework
from auditor.intent import extract_req_ids

_RUN_ID = re.compile(
    r"\b(20\d{6}T\d{6}Z_[0-9a-f]{8})\b",
    re.IGNORECASE,
)
_EVIDENCE_PATH = re.compile(
    r"(?:evidence(?:\s+directory)?|evidence:)\s*`?([^\s`]+)`?",
    re.IGNORECASE,
)
_DOWNLOAD = re.compile(
    r"/v1/downloads/(20\d{6}T\d{6}Z_[0-9a-f]{8})_audit\.zip",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    run_id: str
    framework_id: str
    req_ids: list[str]
    store: EvidenceStore
    source: str  # explicit | history | disk


def extract_run_id(text: str) -> str | None:
    """Pull a run id from free text if present."""
    if not text:
        return None
    match = _RUN_ID.search(text)
    if match:
        return match.group(1)
    path_match = _EVIDENCE_PATH.search(text)
    if path_match:
        segment = Path(path_match.group(1).rstrip("/")).name
        if _RUN_ID.fullmatch(segment):
            return segment
    dl = _DOWNLOAD.search(text)
    if dl:
        return dl.group(1)
    return None


def extract_run_id_from_messages(messages: Sequence[Any]) -> str | None:
    """Scan chat messages (newest first) for an evidence run id."""
    for msg in reversed(list(messages or [])):
        content = getattr(msg, "content", None)
        if content is None and isinstance(msg, dict):
            content = msg.get("content")
        role = getattr(msg, "role", None)
        if role is None and isinstance(msg, dict):
            role = msg.get("role")
        if role not in (None, "assistant", "user", "system"):
            continue
        found = extract_run_id(str(content or ""))
        if found:
            return found
    return None


def latest_run_id(evidence_dir: Path | str) -> str | None:
    """Return the newest run folder under ``evidence_dir`` (by meta/mtime)."""
    root = Path(evidence_dir)
    if not root.is_dir():
        return None
    candidates: list[tuple[str, float]] = []
    for path in root.iterdir():
        if not path.is_dir() or path.name.startswith("."):
            continue
        if not _RUN_ID.fullmatch(path.name):
            continue
        score = path.stat().st_mtime
        meta_path = path / "meta.json"
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                updated = str(meta.get("updated_at") or "")
                if updated:
                    # ISO timestamps sort lexicographically when UTC-Z
                    score = max(score, path.stat().st_mtime)
            except (OSError, json.JSONDecodeError):
                pass
        # Prefer run_id stamp ordering as primary key
        candidates.append((path.name, score))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][0]


def resolve_framework_for_req(
    *,
    user_text: str,
    store: EvidenceStore,
    req_id: str,
    agents_dir: Path,
) -> str:
    """Pick a framework folder that contains ``req_id`` (or from routing)."""
    # Explicit known framework id/alias from text.
    try:
        routed = route_framework(user_text, agents_dir)
        fw_path = store.root / routed.id
        if fw_path.is_dir() and (
            not req_id
            or (fw_path / req_id).is_dir()
            or req_id in store.list_requirement_ids(routed.id)
        ):
            return routed.id
        # Routed fw exists in agents but folder may use same id even if REQ not yet there
        if fw_path.is_dir():
            return routed.id
        # If checklist has the REQ, still prefer routed id for revise
        fw_obj = get_framework(routed.id, agents_dir)
        if fw_obj is not None:
            return routed.id
    except FileNotFoundError:
        pass

    frameworks = store.list_framework_ids()
    if not frameworks:
        meta = store.read_run_meta()
        frameworks = [str(x) for x in (meta.get("frameworks") or []) if x and x != "adhoc"]

    if req_id:
        matches = [fw for fw in frameworks if (store.root / fw / req_id).is_dir()]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(
                f"REQ `{req_id}` exists in multiple frameworks: "
                + ", ".join(f"`{m}`" for m in matches)
                + ". Name the framework in your message."
            )

    if len(frameworks) == 1:
        return frameworks[0]

    if frameworks:
        raise ValueError(
            "Could not determine framework. Mention one of: "
            + ", ".join(f"`{f}`" for f in frameworks)
        )
    raise ValueError("No framework folders found in this audit run.")


def resolve_target(
    *,
    user_text: str,
    evidence_dir: Path | str,
    agents_dir: Path,
    messages: Sequence[Any] | None = None,
    require_req: bool = True,
) -> ResolvedTarget:
    """Resolve run + framework (+ optional REQ ids) for post-audit follow-up."""
    req_ids = extract_req_ids(user_text)
    if require_req and not req_ids:
        raise ValueError("Name at least one requirement id, e.g. `REQ-002`.")

    source = "explicit"
    run_id = extract_run_id(user_text)
    if not run_id and messages:
        run_id = extract_run_id_from_messages(messages)
        if run_id:
            source = "history"
    if not run_id:
        run_id = latest_run_id(evidence_dir)
        source = "disk"
    if not run_id:
        raise FileNotFoundError(
            "No prior audit evidence found. Run a checklist audit first, "
            "or include the run id in your message."
        )

    store = EvidenceStore.open_existing(evidence_dir, run_id)
    req_id = req_ids[0] if req_ids else ""
    framework_id = resolve_framework_for_req(
        user_text=user_text,
        store=store,
        req_id=req_id,
        agents_dir=agents_dir,
    )
    return ResolvedTarget(
        run_id=run_id,
        framework_id=framework_id,
        req_ids=req_ids,
        store=store,
        source=source,
    )

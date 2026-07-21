"""Resolve prior audit run / framework from chat text, history, or disk.

This module centralizes **target resolution** for post-audit follow-up,
ad-hoc attachment, and report rebuild flows. It extracts run ids, host hints,
and framework keys from operator messages and maps them to an open
:class:`~auditor.evidence_store.EvidenceStore`.

Pipeline role:
    Bridges natural-language operator requests ("Evaluate REQ-001 on ubuntu_cis
    for host 10.0.0.1") to concrete ``(run_id, framework_id, req_ids)`` tuples
    used by :mod:`auditor.followup` and :mod:`auditor.adhoc`.

Key entry points:
    :func:`resolve_target` — full resolution for follow-up commands.
    :func:`latest_run_id` — newest evidence folder on disk.
    :func:`extract_run_id` / :func:`extract_run_id_from_messages` — run id from text/history.
    :func:`split_evidence_framework_key` — parse ``host/framework`` evidence keys.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from auditor.evidence_store import EvidenceStore
from auditor.frameworks import route_framework
from auditor.intent import extract_req_ids

_RUN_ID = re.compile(
    r"\b(20\d{6}T\d{6}Z_[0-9a-f]{8})\b",
    re.IGNORECASE,
)
# Client-named artifact folders (after intake): artifacts/TestCompany
_CLIENT_RUN = re.compile(
    r"(?:artifacts|evidence)[/\\]+([A-Za-z0-9._-]{1,64})\b",
    re.IGNORECASE,
)
_EVIDENCE_PATH = re.compile(
    r"(?:evidence\s+directory:?|evidence:)\s*`?([^\s`:][^`\s]*)`?",
    re.IGNORECASE,
)
_DOWNLOAD = re.compile(
    r"/v1/downloads/([A-Za-z0-9._-]{1,64})_audit\.zip",
    re.IGNORECASE,
)
# Host hints for multi-host evidence keys (``10.200.29.78/ubuntu_cis``).
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_HOST_FOR = re.compile(
    r"\b(?:host|on|for|@)\s+([A-Za-z0-9][A-Za-z0-9._-]{0,63})\b",
    re.IGNORECASE,
)
_HOST_FW_PATH = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9][A-Za-z0-9._-]{0,63})"
    r"[/\\]([A-Za-z0-9][A-Za-z0-9._-]{0,63})\b"
)


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """Fully resolved evidence target for a follow-up or ad-hoc operation.

    Attributes:
        run_id: Evidence run folder name (timestamp or client slug).
        framework_id: Evidence key — bare ``ubuntu_cis`` or ``10.0.0.1/ubuntu_cis``.
        req_ids: Requirement ids extracted from operator text (may be empty).
        store: Open :class:`~auditor.evidence_store.EvidenceStore` for the run.
        source: How ``run_id`` was resolved: ``explicit``, ``history``, or ``disk``.
        host_id: Host segment from ``framework_id``, or ``None`` for single-host runs.
    """

    run_id: str
    framework_id: str  # evidence key: ``ubuntu_cis`` or ``10.200.29.78/ubuntu_cis``
    req_ids: list[str]
    store: EvidenceStore
    source: str  # explicit | history | disk
    host_id: str | None = None


def split_evidence_framework_key(key: str) -> tuple[str | None, str]:
    """Split ``host/fw`` evidence keys into ``(host_id, checklist_id)``.

    Args:
        key: Framework folder name under the evidence run.

    Returns:
        Tuple of optional host prefix and bare framework id. For a plain
        ``ubuntu_cis`` key, host is ``None``.
    """
    parts = [p for p in str(key or "").replace("\\", "/").split("/") if p]
    if len(parts) >= 2:
        return parts[0], parts[-1]
    if len(parts) == 1:
        return None, parts[0]
    return None, ""


def checklist_framework_id(framework_key: str) -> str:
    """Return bare checklist id for :func:`~auditor.frameworks.get_framework`.

    Strips any host prefix from a multi-host evidence key.

    Args:
        framework_key: Evidence folder key (may include host prefix).

    Returns:
        Framework id suitable for loading checklist YAML under ``agents/``.
    """
    _host, fw = split_evidence_framework_key(framework_key)
    return fw


def extract_host_hints(text: str) -> list[str]:
    """Extract host IPs and names mentioned in operator text (order preserved).

    Scans for ``host/fw`` path patterns, IPv4 addresses, and ``host|on|for|@``
    prefixed tokens while filtering framework-like noise.

    Args:
        text: Operator message.

    Returns:
        Deduplicated list of host hint strings in discovery order.
    """
    raw = text or ""
    seen: set[str] = set()
    out: list[str] = []

    def _add(value: str) -> None:
        """Append a unique host hint, skipping framework ids and stop-words.

        Args:
            value: Raw host token extracted from the operator message.
        """
        hint = (value or "").strip().rstrip("/\\")
        if not hint or hint.lower() in seen:
            return
        low = hint.lower()
        # Skip common non-host words / framework ids captured by _HOST_FOR.
        if low in {
            "ubuntu",
            "postgres",
            "postgresql",
            "windows",
            "linux",
            "cis",
            "req",
            "the",
            "this",
            "that",
            "host",
            "it_audit",
            "adhoc",
        }:
            return
        if low.endswith("_cis") or low.endswith("_audit"):
            return
        seen.add(low)
        out.append(hint)

    for match in _HOST_FW_PATH.finditer(raw):
        _add(match.group(1))
    for match in _IPV4.finditer(raw):
        _add(match.group(1))
    for match in _HOST_FOR.finditer(raw):
        _add(match.group(1))
    return out


def _key_matches_framework(evidence_key: str, framework_id: str) -> bool:
    """Return True when evidence key is ``fw`` or ``host/fw`` for ``framework_id``.

    Args:
        evidence_key: On-disk framework folder name.
        framework_id: Bare framework id from routing.

    Returns:
        ``True`` on exact match or suffix ``/framework_id``.
    """
    if not framework_id:
        return False
    if evidence_key == framework_id:
        return True
    return evidence_key.endswith(f"/{framework_id}")


def _key_matches_host(evidence_key: str, host_hint: str) -> bool:
    """Return True when evidence key's host segment matches ``host_hint``.

    Args:
        evidence_key: On-disk framework folder (may be ``host/fw``).
        host_hint: Operator-provided host IP, name, or slug.

    Returns:
        ``True`` on exact or substring host match.
    """
    host_id, _fw = split_evidence_framework_key(evidence_key)
    if not host_hint:
        return False
    hint = host_hint.lower()
    if host_id and (host_id.lower() == hint or hint in host_id.lower()):
        return True
    return hint in evidence_key.lower()


def extract_run_id(text: str) -> str | None:
    """Pull a run id (timestamp or client folder name) from free text.

    Matches ISO timestamp run ids, explicit evidence paths, artifact folder
    names, and Open WebUI download URL segments.

    Args:
        text: Operator or assistant message content.

    Returns:
        Run id string, or ``None`` when not found.
    """
    if not text:
        return None
    match = _RUN_ID.search(text)
    if match:
        return match.group(1)
    path_match = _EVIDENCE_PATH.search(text)
    if path_match:
        segment = Path(path_match.group(1).rstrip("/")).name
        if segment and segment not in {".", ".."}:
            return segment
    client = _CLIENT_RUN.search(text)
    if client:
        return client.group(1)
    dl = _DOWNLOAD.search(text)
    if dl:
        return dl.group(1)
    return None


def extract_run_id_from_messages(messages: Sequence[Any]) -> str | None:
    """Scan chat messages (newest first) for an evidence run id.

    Args:
        messages: Chat history (dicts or LangChain messages).

    Returns:
        First run id found in assistant/user/system content, or ``None``.
    """
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
    """Return the newest run folder under ``evidence_dir`` (by meta/mtime).

    Skips empty placeholder directories without ``meta.json``. Prefers
    ``updated_at`` / ``created_at`` from meta when present.

    Args:
        evidence_dir: Root artifacts/evidence directory.

    Returns:
        Newest run folder name, or ``None`` when no candidates exist.
    """
    root = Path(evidence_dir)
    if not root.is_dir():
        return None
    candidates: list[tuple[str, float]] = []
    for path in root.iterdir():
        if not path.is_dir() or path.name.startswith("."):
            continue
        # Skip empty placeholder dirs without meta
        meta_path = path / "meta.json"
        score = path.stat().st_mtime
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                updated = str(meta.get("updated_at") or meta.get("created_at") or "")
                if updated:
                    score = max(score, path.stat().st_mtime)
            except (OSError, json.JSONDecodeError):
                pass
        elif not any(path.iterdir()):
            continue
        candidates.append((path.name, score))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[1], reverse=True)
    return candidates[0][0]


def _disambiguate_framework_matches(
    matches: list[str],
    *,
    user_text: str,
    agents_dir: Path,
    req_id: str,
) -> str:
    """Narrow ``host/fw`` (or plain fw) matches using host + framework hints.

    Args:
        matches: Candidate evidence framework keys containing the REQ.
        user_text: Operator message for host/framework disambiguation.
        agents_dir: Path to ``agents/`` for :func:`~auditor.frameworks.route_framework`.
        req_id: Requirement id (used in error messages).

    Returns:
        Single chosen evidence framework key.

    Raises:
        ValueError: When multiple matches remain after narrowing.
    """
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError("No matching framework evidence found.")

    narrowed = list(matches)
    host_hints = extract_host_hints(user_text)
    # Prefer IPv4 hints when present (ignore framework-like noise).
    preferred_hosts = [h for h in host_hints if _IPV4.fullmatch(h)] or host_hints
    if preferred_hosts:
        by_host = [
            m
            for m in narrowed
            if any(_key_matches_host(m, hint) for hint in preferred_hosts)
        ]
        if len(by_host) == 1:
            return by_host[0]
        if by_host:
            narrowed = by_host

    try:
        routed = route_framework(user_text, agents_dir)
    except FileNotFoundError:
        routed = None

    if routed is not None:
        by_fw = [m for m in narrowed if _key_matches_framework(m, routed.id)]
        if len(by_fw) == 1:
            return by_fw[0]
        if by_fw:
            narrowed = by_fw
        # Explicit path-like mention already in text (host/fw).
        for m in narrowed:
            if m.lower() in (user_text or "").lower():
                return m

    label = f"REQ `{req_id}`" if req_id else "this request"
    raise ValueError(
        f"{label} exists in multiple frameworks/hosts: "
        + ", ".join(f"`{m}`" for m in matches)
        + ". Name the host and framework, e.g. "
        "`Evaluate REQ-001 on ubuntu_cis for host 10.200.29.78`."
    )


def resolve_framework_for_req(
    *,
    user_text: str,
    store: EvidenceStore,
    req_id: str,
    agents_dir: Path,
) -> str:
    """Pick a framework folder that contains ``req_id`` (or from routing).

    Resolution order: on-disk REQ folders, routed framework from text,
    single-framework run fallback, or explicit error when ambiguous.

    Args:
        user_text: Operator message (framework aliases and host hints).
        store: Open evidence store for the target run.
        req_id: Requirement id to locate (may be empty for framework-only).
        agents_dir: Path to framework definitions.

    Returns:
        Evidence key: bare ``ubuntu_cis`` or ``10.200.29.78/ubuntu_cis``.

    Raises:
        ValueError: When framework cannot be determined or is ambiguous.
    """
    frameworks = store.list_framework_ids()
    if not frameworks:
        meta = store.read_run_meta()
        frameworks = [
            str(x) for x in (meta.get("frameworks") or []) if x and x != "adhoc"
        ]

    # Prefer on-disk evidence that already contains this REQ.
    if req_id:
        matches = [fw for fw in frameworks if (store.root / fw / req_id).is_dir()]
        if matches:
            return _disambiguate_framework_matches(
                matches,
                user_text=user_text,
                agents_dir=agents_dir,
                req_id=req_id,
            )

    # Explicit known framework id/alias from text (must exist in this run).
    try:
        routed = route_framework(user_text, agents_dir)
        fw_path = store.root / routed.id
        if fw_path.is_dir():
            return routed.id
        # Alias mentioned but folder not created yet — only if single framework run.
        if len(frameworks) == 1:
            return frameworks[0]
        fw_matches = [m for m in frameworks if _key_matches_framework(m, routed.id)]
        if fw_matches:
            return _disambiguate_framework_matches(
                fw_matches,
                user_text=user_text,
                agents_dir=agents_dir,
                req_id=req_id,
            )
        # Text clearly names a framework that has a checklist even if empty folder.
        lowered = (user_text or "").lower()
        if routed.id.lower() in lowered or any(
            a.lower() in lowered for a in (routed.aliases or [])
        ):
            return routed.id
    except FileNotFoundError:
        pass

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
    """Resolve run + framework (+ optional REQ ids) for post-audit follow-up.

    Args:
        user_text: Operator message.
        evidence_dir: Root evidence/artifacts directory.
        agents_dir: Framework definitions directory.
        messages: Optional chat history for run-id fallback.
        require_req: When True, raises if no REQ-* id is present in text.

    Returns:
        :class:`ResolvedTarget` with open store and resolved framework key.

    Raises:
        ValueError: When REQ is required but missing, or framework is ambiguous.
        FileNotFoundError: When no evidence run exists on disk.
    """
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
    host_id, _bare = split_evidence_framework_key(framework_id)
    return ResolvedTarget(
        run_id=run_id,
        framework_id=framework_id,
        req_ids=req_ids,
        store=store,
        source=source,
        host_id=host_id,
    )

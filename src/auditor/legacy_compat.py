"""Compatibility adapter and CORE-001 identity helpers.

Identity field meanings
-----------------------
``client_id``
    Durable client registry id (typically ``client_<hex>``). Permanently
    identifies one client across many audits. Never an execution id.
``audit_run_id``
    Business id of one audit execution (``arun_<hex>``). One client may own
    many runs; runs are never interchangeable by client alone.
``evidence_run_id`` / API ``run_id``
    On-disk evidence folder key, normally ``<client_slug>/<audit_run_id>``.
    Legacy flat layouts used the client folder name as this value. This is
    **not** a substitute for ``audit_run_id`` and must not be copied into
    ``client_id``.
``thread_id`` / ``checkpoint_id``
    LangGraph checkpoint thread identifiers. Resume must also bind an
    explicit ``audit_run_id``; thread id alone must not select "latest" run.

Legacy layouts used the client folder name as the evidence "run id". This
module never guesses a single active run from client name/slug/latest —
ambiguous cases raise :class:`AmbiguousLegacyRunError`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from auditor.client_registry import looks_like_audit_run_id


class AmbiguousLegacyRunError(ValueError):
    """Raised when legacy data cannot be mapped to exactly one AuditRun."""

    def __init__(self, message: str, *, candidates: list[str] | None = None) -> None:
        self.candidates = list(candidates or [])
        detail = message
        if self.candidates:
            detail += " candidates=" + ", ".join(repr(c) for c in self.candidates)
        super().__init__(detail)


class MissingAuditRunIdError(ValueError):
    """Raised when a run-scoped operation lacks an explicit audit_run_id."""


class MissingClientIdError(ValueError):
    """Raised when a client-scoped operation lacks an explicit client_id."""


class ClientOwnershipError(ValueError):
    """Raised when an audit run's client ownership would be violated."""


@dataclass(frozen=True, slots=True)
class LegacyEvidenceHit:
    """One on-disk evidence root discovered by the adapter."""

    evidence_path: str
    evidence_run_id: str
    client_id: str
    audit_run_id: str
    client_slug: str
    status: str
    legacy: bool


def _read_meta(path: Path) -> dict[str, Any]:
    meta_path = path / "meta.json"
    if not meta_path.is_file():
        return {}
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def iter_evidence_roots(evidence_dir: Path | str) -> list[LegacyEvidenceHit]:
    """List evidence roots in nested (CORE-001) and flat (legacy) layouts."""
    root = Path(evidence_dir)
    if not root.is_dir():
        return []
    hits: list[LegacyEvidenceHit] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        # Nested: <client_slug>/<audit_run_id>/
        nested_runs = [p for p in child.iterdir() if p.is_dir() and not p.name.startswith(".")]
        has_nested_arun = any(
            looks_like_audit_run_id(p.name) or _read_meta(p).get("audit_run_id")
            for p in nested_runs
        )
        if has_nested_arun:
            for run_dir in nested_runs:
                meta = _read_meta(run_dir)
                arun = str(meta.get("audit_run_id") or "").strip()
                if not arun and looks_like_audit_run_id(run_dir.name):
                    arun = run_dir.name
                hits.append(
                    LegacyEvidenceHit(
                        evidence_path=str(run_dir),
                        evidence_run_id=f"{child.name}/{run_dir.name}",
                        client_id=str(meta.get("client_id") or ""),
                        audit_run_id=arun,
                        client_slug=str(meta.get("client_slug") or child.name),
                        status=str(meta.get("status") or ""),
                        legacy=not bool(meta.get("audit_run_id")),
                    )
                )
            continue
        # Flat legacy: <ClientName>/meta.json
        meta = _read_meta(child)
        if not meta and not any(child.iterdir()):
            continue
        hits.append(
            LegacyEvidenceHit(
                evidence_path=str(child),
                evidence_run_id=child.name,
                client_id=str(meta.get("client_id") or ""),
                audit_run_id=str(meta.get("audit_run_id") or ""),
                client_slug=str(meta.get("client_slug") or child.name),
                status=str(meta.get("status") or ""),
                legacy=not bool(meta.get("audit_run_id")),
            )
        )
    return hits


def resolve_evidence_for_audit_run(
    evidence_dir: Path | str,
    audit_run_id: str,
) -> LegacyEvidenceHit:
    """Resolve exactly one evidence root for an explicit ``audit_run_id``."""
    arun = (audit_run_id or "").strip()
    if not arun:
        raise MissingAuditRunIdError("audit_run_id is required to resolve evidence")
    if not looks_like_audit_run_id(arun) and not arun.startswith("arun_"):
        # Reject client slug / display name used as run id.
        raise MissingAuditRunIdError(
            f"value {arun!r} is not an audit_run_id (client name/slug cannot identify a run)"
        )
    matches = [
        h
        for h in iter_evidence_roots(evidence_dir)
        if h.audit_run_id == arun
        or h.evidence_run_id.endswith(f"/{arun}")
        or h.evidence_run_id == arun
    ]
    if not matches:
        raise KeyError(f"No evidence found for audit_run_id={arun!r}")
    if len(matches) > 1:
        raise AmbiguousLegacyRunError(
            f"multiple evidence roots for audit_run_id={arun!r}",
            candidates=[m.evidence_run_id for m in matches],
        )
    return matches[0]


def report_legacy_without_audit_run(
    evidence_dir: Path | str,
    *,
    client_slug: str = "",
) -> list[LegacyEvidenceHit]:
    """Return legacy evidence roots that lack ``audit_run_id`` (no guessing)."""
    hits = iter_evidence_roots(evidence_dir)
    out = [h for h in hits if h.legacy or not h.audit_run_id]
    if client_slug:
        slug = client_slug.strip().lower()
        out = [h for h in out if h.client_slug.lower() == slug]
    return out


def require_audit_run_id(audit_run_id: str | None, *, context: str = "") -> str:
    """Validate an explicit audit_run_id for run-scoped operations."""
    value = (audit_run_id or "").strip()
    if not value:
        raise MissingAuditRunIdError(
            "audit_run_id is required" + (f" for {context}" if context else "")
        )
    if looks_like_audit_run_id(value):
        return value
    # Reject client slug / bare names as run ids.
    raise MissingAuditRunIdError(
        f"invalid audit_run_id {value!r}"
        + (f" for {context}" if context else "")
        + "; client name/slug cannot be used as a run id"
    )


def require_client_id(client_id: str | None, *, context: str = "") -> str:
    """Validate an explicit non-empty ``client_id`` (CORE-001).

    Rejects ``None``, empty, whitespace-only, and values that look like an
    ``audit_run_id`` so identifiers are never silently swapped.
    """
    value = (client_id or "").strip()
    if not value:
        raise MissingClientIdError("client_id is required" + (f" for {context}" if context else ""))
    if looks_like_audit_run_id(value):
        raise MissingClientIdError(
            f"invalid client_id {value!r}"
            + (f" for {context}" if context else "")
            + "; audit_run_id cannot be used as client_id"
        )
    return value


def assert_client_owns_run(
    *,
    audit_run_id: str,
    run_client_id: str | None,
    requested_client_id: str | None,
    context: str = "",
) -> str:
    """Ensure ``requested_client_id`` matches the run's stored client ownership.

    Returns the normalized requested client id. Empty stored ownership may be
    backfilled once; a non-empty mismatch raises :class:`ClientOwnershipError`.
    """
    requested = require_client_id(requested_client_id, context=context or "client ownership")
    stored = (run_client_id or "").strip()
    if stored and stored != requested:
        raise ClientOwnershipError(
            f"audit_run_id {audit_run_id!r} belongs to client_id={stored!r}, "
            f"not {requested!r}" + (f" ({context})" if context else "")
        )
    return requested

"""Canonical audit-run storage scope (CORE-005).

All LangGraph checkpoints and run-owned artifacts are bound to validated
``client_id`` + ``audit_run_id``. Callers must not construct storage paths or
checkpoint thread ids independently.

Identity meanings
-----------------
``client_id`` / ``audit_run_id``
    Canonical business identity (see :mod:`auditor.legacy_compat`).
``thread_id``
    LangGraph checkpoint thread only. Derived as
    ``audit:<client_id>:<audit_run_id>[:namespace…]``.
``evidence_run_id``
    On-disk folder key ``<client_slug>/<audit_run_id>`` (slug is a filesystem
    label; ownership is proven by ``ownership.json``, not the slug).

Legacy flat ``<ClientName>/`` evidence trees are read-only compatible when
ownership can be proven; ambiguous ownership fails closed.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from auditor.legacy_compat import (
    require_audit_run_id,
    require_client_id,
)

OWNERSHIP_MANIFEST_NAME = "ownership.json"
OWNERSHIP_SCHEMA_VERSION = 1
CHECKPOINT_KEY_PREFIX = "audit"
_SAFE_SEGMENT = re.compile(r"[^A-Za-z0-9._-]+")
_PROTECTED_BASENAMES = frozenset(
    {
        OWNERSHIP_MANIFEST_NAME,
        "meta.json",
        ".langgraph_checkpoints.sqlite",
        ".langgraph_checkpoints.sqlite-wal",
        ".langgraph_checkpoints.sqlite-shm",
    }
)


class RunScopeIsolationError(ValueError):
    """Raised when checkpoint/artifact access would cross audit-run boundaries."""


class OwnershipManifestError(RunScopeIsolationError):
    """Raised when ownership metadata is missing, malformed, or conflicting."""


@dataclass(frozen=True, slots=True)
class OwnershipManifest:
    """Trusted identity written at each run artifact root."""

    client_id: str
    audit_run_id: str
    schema_version: int = OWNERSHIP_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "audit_run_id": self.audit_run_id,
            "schema_version": int(self.schema_version),
        }


@dataclass(frozen=True, slots=True)
class RunScope:
    """Resolved checkpoint + artifact scope for one audit run."""

    client_id: str
    audit_run_id: str
    client_slug: str
    evidence_dir: Path
    artifact_root: Path
    evidence_run_id: str
    checkpoint_thread_id: str
    checkpoint_db_path: Path

    @property
    def ownership(self) -> OwnershipManifest:
        return OwnershipManifest(client_id=self.client_id, audit_run_id=self.audit_run_id)


def safe_path_segment(value: str, *, fallback: str = "x") -> str:
    """Sanitize one path segment; reject empty / traversal tokens."""
    text = (value or "").strip().replace("\\", "/")
    if not text or text in {".", ".."} or "/" in text:
        raise RunScopeIsolationError(f"invalid path segment {value!r}")
    cleaned = _SAFE_SEGMENT.sub("_", text).strip("._-")
    if not cleaned or cleaned in {".", ".."}:
        raise RunScopeIsolationError(f"invalid path segment {value!r}")
    return cleaned


def checkpoint_thread_id(client_id: str, audit_run_id: str, *namespace: str) -> str:
    """Deterministic LangGraph thread id for an audit run (optional namespace).

    Format: ``audit:<client_id>:<audit_run_id>[:ns…]``.
    """
    cid = require_client_id(client_id, context="checkpoint_thread_id")
    arid = require_audit_run_id(audit_run_id, context="checkpoint_thread_id")
    parts = [CHECKPOINT_KEY_PREFIX, cid, arid]
    for part in namespace:
        seg = str(part or "").strip()
        if not seg:
            continue
        # Namespace labels must not inject extra ``audit:`` roots or path chars.
        if "/" in seg or "\\" in seg or ".." in seg:
            raise RunScopeIsolationError(f"invalid checkpoint namespace {part!r}")
        parts.append(seg.replace(":", "_"))
    return ":".join(parts)


def parse_checkpoint_thread_id(thread_id: str) -> tuple[str, str] | None:
    """Extract ``(client_id, audit_run_id)`` from a canonical checkpoint thread.

    Returns ``None`` for pre-identity / non-canonical threads.
    """
    parts = (thread_id or "").strip().split(":")
    if len(parts) < 3 or parts[0] != CHECKPOINT_KEY_PREFIX:
        return None
    try:
        cid = require_client_id(parts[1], context="parse_checkpoint_thread_id")
        arid = require_audit_run_id(parts[2], context="parse_checkpoint_thread_id")
    except Exception:  # noqa: BLE001
        return None
    return cid, arid


def assert_thread_belongs_to_run(
    thread_id: str,
    *,
    client_id: str,
    audit_run_id: str,
    context: str = "",
    registered_base_thread_id: str = "",
) -> str:
    """Ensure ``thread_id`` is in the run's checkpoint namespace.

    Accepts the canonical ``audit:<client_id>:<audit_run_id>[:…]`` form, or a
    registered pre-identity base thread (intake before IDs existed) that is
    recorded on the AuditRun — never an arbitrary foreign thread.
    """
    tid = (thread_id or "").strip()
    base = checkpoint_thread_id(client_id, audit_run_id)
    if tid == base or tid.startswith(base + ":"):
        return tid
    reg = (registered_base_thread_id or "").strip()
    if reg and (tid == reg or tid.startswith(reg + ":")):
        return tid
    suffix = f" ({context})" if context else ""
    raise RunScopeIsolationError(
        f"thread_id {tid!r} is not in checkpoint scope for "
        f"client_id={client_id!r} audit_run_id={audit_run_id!r}{suffix}"
    )


def evidence_run_id_for(client_slug: str, audit_run_id: str) -> str:
    """Relative evidence key ``<slug>/<audit_run_id>`` under the artifact root."""
    arid = require_audit_run_id(audit_run_id, context="evidence_run_id_for")
    slug = safe_path_segment(client_slug, fallback="client")
    return f"{slug}/{arid}"


def resolve_run_scope(
    evidence_dir: Path | str,
    *,
    client_id: str,
    audit_run_id: str,
    client_slug: str | None = None,
) -> RunScope:
    """Resolve canonical checkpoint + artifact paths from validated identity."""
    cid = require_client_id(client_id, context="resolve_run_scope")
    arid = require_audit_run_id(audit_run_id, context="resolve_run_scope")
    root = Path(evidence_dir).resolve()
    slug = safe_path_segment(client_slug or cid, fallback="client")
    evid = evidence_run_id_for(slug, arid)
    artifact_root = root.joinpath(*evid.split("/"))
    # Checkpoints live beside evidence under a dedicated tree (not shared file).
    ckpt = root / ".checkpoints" / safe_path_segment(cid) / f"{safe_path_segment(arid)}.sqlite"
    return RunScope(
        client_id=cid,
        audit_run_id=arid,
        client_slug=slug,
        evidence_dir=root,
        artifact_root=artifact_root,
        evidence_run_id=evid,
        checkpoint_thread_id=checkpoint_thread_id(cid, arid),
        checkpoint_db_path=ckpt,
    )


def write_ownership_manifest(artifact_root: Path | str, ownership: OwnershipManifest) -> Path:
    """Write ``ownership.json``; refuse silent ownership rewrite conflicts."""
    root = Path(artifact_root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / OWNERSHIP_MANIFEST_NAME
    if path.is_file():
        existing = read_ownership_manifest(root)
        if (
            existing.client_id != ownership.client_id
            or existing.audit_run_id != ownership.audit_run_id
        ):
            raise OwnershipManifestError(
                f"refusing to rewrite ownership at {path}: "
                f"existing=({existing.client_id!r}, {existing.audit_run_id!r}) "
                f"requested=({ownership.client_id!r}, {ownership.audit_run_id!r})"
            )
        return path
    path.write_text(
        json.dumps(ownership.as_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def read_ownership_manifest(artifact_root: Path | str) -> OwnershipManifest:
    """Load and validate ownership metadata (fail closed)."""
    path = Path(artifact_root) / OWNERSHIP_MANIFEST_NAME
    if not path.is_file():
        raise OwnershipManifestError(f"missing ownership manifest at {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OwnershipManifestError(f"malformed ownership manifest at {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise OwnershipManifestError(f"malformed ownership manifest at {path}: not an object")
    try:
        cid = require_client_id(str(data.get("client_id") or ""), context="ownership.json")
        arid = require_audit_run_id(str(data.get("audit_run_id") or ""), context="ownership.json")
        ver = int(data.get("schema_version") or 0)
    except (TypeError, ValueError) as exc:
        raise OwnershipManifestError(f"malformed ownership manifest at {path}: {exc}") from exc
    if ver != OWNERSHIP_SCHEMA_VERSION:
        raise OwnershipManifestError(
            f"unsupported ownership schema_version={ver} at {path} "
            f"(expected {OWNERSHIP_SCHEMA_VERSION})"
        )
    return OwnershipManifest(client_id=cid, audit_run_id=arid, schema_version=ver)


def ensure_ownership_manifest(
    artifact_root: Path | str,
    *,
    client_id: str,
    audit_run_id: str,
) -> OwnershipManifest:
    """Create ownership.json for a new root or validate an existing one."""
    ownership = OwnershipManifest(
        client_id=require_client_id(client_id, context="ensure_ownership"),
        audit_run_id=require_audit_run_id(audit_run_id, context="ensure_ownership"),
    )
    root = Path(artifact_root)
    if (root / OWNERSHIP_MANIFEST_NAME).is_file():
        existing = read_ownership_manifest(root)
        if (
            existing.client_id != ownership.client_id
            or existing.audit_run_id != ownership.audit_run_id
        ):
            raise OwnershipManifestError(
                f"ownership mismatch at {root}: "
                f"manifest=({existing.client_id!r}, {existing.audit_run_id!r}) "
                f"expected=({ownership.client_id!r}, {ownership.audit_run_id!r})"
            )
        return existing
    write_ownership_manifest(root, ownership)
    return ownership


def assert_ownership(
    artifact_root: Path | str,
    *,
    client_id: str,
    audit_run_id: str,
    context: str = "",
) -> OwnershipManifest:
    """Validate manifest matches the requested identity exactly."""
    cid = require_client_id(client_id, context=context or "assert_ownership")
    arid = require_audit_run_id(audit_run_id, context=context or "assert_ownership")
    manifest = read_ownership_manifest(artifact_root)
    if manifest.client_id != cid or manifest.audit_run_id != arid:
        raise OwnershipManifestError(
            "ownership mismatch"
            + (f" ({context})" if context else "")
            + f": manifest=({manifest.client_id!r}, {manifest.audit_run_id!r}) "
            f"requested=({cid!r}, {arid!r})"
        )
    return manifest


def verify_registry_ownership(
    *,
    audit_run_id: str,
    run_client_id: str | None,
    requested_client_id: str | None,
    context: str = "",
) -> str:
    """CORE-001 ownership check used by resume / open paths."""
    from auditor.legacy_compat import assert_client_owns_run

    return assert_client_owns_run(
        audit_run_id=audit_run_id,
        run_client_id=run_client_id,
        requested_client_id=requested_client_id,
        context=context or "run_scope",
    )


def resolve_under_run_root(run_root: Path | str, *parts: str) -> Path:
    """Join path parts under ``run_root``; reject escape / absolute / protected names."""
    root = Path(run_root).resolve()
    if not parts:
        return root
    segs: list[str] = []
    for raw in parts:
        text = str(raw or "").replace("\\", "/").strip()
        if not text:
            raise RunScopeIsolationError("empty artifact path segment")
        if text.startswith("/") or (len(text) > 1 and text[1] == ":"):
            raise RunScopeIsolationError(f"absolute artifact path rejected: {raw!r}")
        for piece in text.split("/"):
            if not piece or piece in {".", ".."}:
                raise RunScopeIsolationError(f"path traversal rejected: {raw!r}")
            segs.append(safe_path_segment(piece))
    if segs and segs[0] in _PROTECTED_BASENAMES:
        raise RunScopeIsolationError(f"refusing to overwrite protected path {segs[0]!r}")
    resolved = root.joinpath(*segs).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RunScopeIsolationError(f"artifact path escapes run root {root}: {resolved}") from exc
    return resolved


def cleanup_run_scope(scope: RunScope, *, missing_ok: bool = True) -> None:
    """Delete only the exact artifact root and per-run checkpoint DB."""
    art = scope.artifact_root
    if art.is_dir():
        # Refuse cleanup when ownership does not match (fail closed).
        assert_ownership(
            art,
            client_id=scope.client_id,
            audit_run_id=scope.audit_run_id,
            context="cleanup_run_scope",
        )
        shutil.rmtree(art)
    elif not missing_ok:
        raise FileNotFoundError(f"artifact root missing: {art}")
    ckpt = scope.checkpoint_db_path
    for path in (ckpt, Path(str(ckpt) + "-wal"), Path(str(ckpt) + "-shm")):
        if path.is_file():
            path.unlink()
    # Remove empty parent dirs under .checkpoints/<client_id>/ only.
    parent = ckpt.parent
    if parent.is_dir() and not any(parent.iterdir()):
        parent.rmdir()


def open_run_scope(
    evidence_dir: Path | str,
    *,
    client_id: str,
    audit_run_id: str,
    client_slug: str | None = None,
    create: bool = False,
) -> RunScope:
    """Resolve scope, optionally create root + ownership, else validate existing."""
    scope = resolve_run_scope(
        evidence_dir,
        client_id=client_id,
        audit_run_id=audit_run_id,
        client_slug=client_slug,
    )
    if create:
        scope.artifact_root.mkdir(parents=True, exist_ok=True)
        ensure_ownership_manifest(
            scope.artifact_root,
            client_id=scope.client_id,
            audit_run_id=scope.audit_run_id,
        )
        return scope
    if not scope.artifact_root.is_dir():
        raise FileNotFoundError(
            f"audit-run artifact root missing for "
            f"client_id={scope.client_id!r} audit_run_id={scope.audit_run_id!r}: "
            f"{scope.artifact_root}"
        )
    assert_ownership(
        scope.artifact_root,
        client_id=scope.client_id,
        audit_run_id=scope.audit_run_id,
        context="open_run_scope",
    )
    return scope

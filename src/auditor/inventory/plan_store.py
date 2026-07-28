"""Immutable audit-plan revision store with a concurrency-safe latest pointer.

Layout under ``{client}/.audit_plans/``::

    revisions/<plan_revision_id>/{plan,effective.inventory}.json
    latest.pointer.json
    latest.json                  # compatibility materialized view
    effective.inventory.json     # compatibility materialized view
    .plan-store.lock

Operator adjustment actions (exclude_host / exclude_framework / add_framework,
etc.) are deferred to INPUT005-19. This store never mutates immutable revision
files; confirmation/rejection results are materialized only into the
compatibility working plan while the pointer stays on the analysis revision.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from auditor.domain.audit_plan import AuditPlan, PlanConfirmationRejected
from auditor.domain.inventory import ClientInventory

POINTER_SCHEMA_VERSION = "plan-pointer.v1"
POINTER_FILENAME = "latest.pointer.json"
LATEST_PLAN_FILENAME = "latest.json"
EFFECTIVE_INVENTORY_FILENAME = "effective.inventory.json"
LOCK_FILENAME = ".plan-store.lock"
REVISIONS_DIRNAME = "revisions"
_PLAN_REVISION_ID_RE = re.compile(r"^prev-[0-9a-f]{16}$")


class PlanStoreError(PlanConfirmationRejected):
    """Typed plan-store failure (codes map to API/CLI contracts)."""


@dataclass(frozen=True)
class PlanRevisionSnapshot:
    """Immutable plan + effective inventory for one plan_revision_id."""

    plan: AuditPlan
    effective_inventory: ClientInventory
    plan_path: Path
    inventory_path: Path


@dataclass(frozen=True)
class LatestPointer:
    """Validated latest.pointer.json payload."""

    schema_version: str
    plan_id: str
    plan_revision_id: str
    plan_path: str
    effective_inventory_path: str

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "plan_revision_id": self.plan_revision_id,
            "plan_path": self.plan_path,
            "effective_inventory_path": self.effective_inventory_path,
        }


def validate_plan_revision_id(
    value: str,
    *,
    pointer_context: bool = False,
) -> str:
    """Reject traversal / malformed revision identifiers before path construction."""
    revision_id = value.strip()
    if not _PLAN_REVISION_ID_RE.fullmatch(revision_id):
        raise PlanStoreError(
            "invalid plan revision identifier",
            code=("invalid_plan_pointer" if pointer_context else "plan_revision_not_found"),
        )
    return revision_id


def _canonical_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _safe_inventory_dump(inventory: ClientInventory) -> dict[str, Any]:
    """Serialize inventory without embedding secret values."""
    data = inventory.model_dump()
    for cred in data.get("credentials") or []:
        if isinstance(cred, dict):
            cred.pop("secret", None)
            cred.pop("password", None)
    blob = json.dumps(data)
    if "password" in blob.lower() and "password_encryption" not in blob.lower():
        for cred in data.get("credentials") or []:
            if isinstance(cred, dict):
                for key in list(cred):
                    if "password" in key.lower() or key.lower() in {"secret", "token"}:
                        if key not in {"secret_ref", "has_secret"}:
                            cred.pop(key, None)
    return data


def _semantic_plan_payload(plan: AuditPlan) -> dict[str, Any]:
    payload = plan.model_dump()
    payload.pop("created_at", None)
    return payload


def _semantic_inventory_payload(inventory: ClientInventory) -> dict[str, Any]:
    payload = _safe_inventory_dump(inventory)
    version = payload.get("version")
    if isinstance(version, dict):
        version.pop("recorded_at", None)
    return payload


def _same_semantic_revision(
    stored_plan: AuditPlan,
    stored_inventory: ClientInventory,
    candidate_plan: AuditPlan,
    candidate_inventory: ClientInventory,
) -> bool:
    return _semantic_plan_payload(stored_plan) == _semantic_plan_payload(
        candidate_plan
    ) and _semantic_inventory_payload(stored_inventory) == _semantic_inventory_payload(
        candidate_inventory
    )


def _atomic_write_text(path: Path, text: str) -> None:
    """Write ``text`` atomically via temp file + ``os.replace`` in ``path.parent``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _fsync_file(path: Path) -> None:
    with open(path, "rb") as handle:
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_bytes_or_none(path: Path) -> bytes | None:
    if not path.is_file():
        return None
    return path.read_bytes()


def _restore_bytes(path: Path, previous: bytes | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # Direct write is intentional for rollback (avoid nested replace failures).
    path.write_bytes(previous)
    _fsync_file(path)


def _is_safe_relative(path_text: str) -> bool:
    if not path_text or path_text.startswith(("/", "\\")):
        return False
    parts = Path(path_text).parts
    if any(part in {"", ".", ".."} for part in parts):
        return False
    if Path(path_text).is_absolute():
        return False
    return True


def _rmtree_quiet(path: Path) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


class PlanRevisionStore:
    """Per-client immutable revision store with a process-safe latest pointer."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    @property
    def revisions_dir(self) -> Path:
        return self.root / REVISIONS_DIRNAME

    @property
    def pointer_path(self) -> Path:
        return self.root / POINTER_FILENAME

    @property
    def latest_plan_path(self) -> Path:
        return self.root / LATEST_PLAN_FILENAME

    @property
    def latest_inventory_path(self) -> Path:
        return self.root / EFFECTIVE_INVENTORY_FILENAME

    @property
    def lock_path(self) -> Path:
        return self.root / LOCK_FILENAME

    def revision_dir(self, plan_revision_id: str) -> Path:
        rev = validate_plan_revision_id(plan_revision_id)
        return self.revisions_dir / rev

    def revision_plan_path(self, plan_revision_id: str) -> Path:
        return self.revision_dir(plan_revision_id) / "plan.json"

    def revision_inventory_path(self, plan_revision_id: str) -> Path:
        return self.revision_dir(plan_revision_id) / EFFECTIVE_INVENTORY_FILENAME

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - non-POSIX
            raise PlanStoreError(
                "plan store lock unavailable",
                code="plan_store_lock_failed",
            ) from exc

        try:
            self.root.mkdir(parents=True, exist_ok=True)
            lock_file = open(self.lock_path, "a+", encoding="utf-8")
        except OSError as exc:
            raise PlanStoreError(
                "plan store lock unavailable",
                code="plan_store_lock_failed",
            ) from exc

        locked = False
        try:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                locked = True
            except OSError as exc:
                raise PlanStoreError(
                    "plan store lock unavailable",
                    code="plan_store_lock_failed",
                ) from exc
            yield
        finally:
            if locked:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            lock_file.close()

    def _pointer_from_plan(self, plan: AuditPlan) -> LatestPointer:
        rev = validate_plan_revision_id(plan.plan_revision_id, pointer_context=True)
        return LatestPointer(
            schema_version=POINTER_SCHEMA_VERSION,
            plan_id=plan.plan_id,
            plan_revision_id=rev,
            plan_path=f"{REVISIONS_DIRNAME}/{rev}/plan.json",
            effective_inventory_path=(f"{REVISIONS_DIRNAME}/{rev}/{EFFECTIVE_INVENTORY_FILENAME}"),
        )

    def _validate_pointer_payload(self, raw: Any) -> LatestPointer:
        if not isinstance(raw, dict):
            raise PlanStoreError(
                "invalid plan pointer: expected object",
                code="invalid_plan_pointer",
            )
        schema = str(raw.get("schema_version") or "")
        if schema != POINTER_SCHEMA_VERSION:
            raise PlanStoreError(
                "invalid plan pointer: unsupported schema_version",
                code="invalid_plan_pointer",
            )
        plan_id = str(raw.get("plan_id") or "").strip()
        plan_revision_id = str(raw.get("plan_revision_id") or "").strip()
        plan_path = str(raw.get("plan_path") or "").strip()
        inv_path = str(raw.get("effective_inventory_path") or "").strip()
        if not plan_id:
            raise PlanStoreError(
                "invalid plan pointer: missing identifiers",
                code="invalid_plan_pointer",
            )
        rev = validate_plan_revision_id(plan_revision_id, pointer_context=True)
        if not _is_safe_relative(plan_path) or not _is_safe_relative(inv_path):
            raise PlanStoreError(
                "invalid plan pointer: unsafe path",
                code="invalid_plan_pointer",
            )
        expected_plan = f"{REVISIONS_DIRNAME}/{rev}/plan.json"
        expected_inv = f"{REVISIONS_DIRNAME}/{rev}/{EFFECTIVE_INVENTORY_FILENAME}"
        if plan_path != expected_plan or inv_path != expected_inv:
            raise PlanStoreError(
                "invalid plan pointer: revision path mismatch",
                code="invalid_plan_pointer",
            )
        return LatestPointer(
            schema_version=schema,
            plan_id=plan_id,
            plan_revision_id=rev,
            plan_path=plan_path,
            effective_inventory_path=inv_path,
        )

    def _read_pointer_unlocked(self) -> LatestPointer | None:
        if not self.pointer_path.is_file():
            return None
        try:
            raw = json.loads(self.pointer_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PlanStoreError(
                "invalid plan pointer: malformed JSON",
                code="invalid_plan_pointer",
            ) from exc
        return self._validate_pointer_payload(raw)

    def _load_plan_file(self, path: Path) -> AuditPlan:
        if not path.is_file():
            raise PlanStoreError(
                "plan revision not found",
                code="plan_revision_not_found",
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return AuditPlan.model_validate(data)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise PlanStoreError(
                "plan revision not found",
                code="plan_revision_not_found",
            ) from exc

    def _load_inventory_file(self, path: Path) -> ClientInventory:
        if not path.is_file():
            raise PlanStoreError(
                "plan revision not found",
                code="plan_revision_not_found",
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return ClientInventory.model_validate(data)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise PlanStoreError(
                "plan revision not found",
                code="plan_revision_not_found",
            ) from exc

    def _snapshot_from_revision_dir(self, rev: str) -> PlanRevisionSnapshot:
        plan_path = self.revision_plan_path(rev)
        inv_path = self.revision_inventory_path(rev)
        plan = self._load_plan_file(plan_path)
        if plan.plan_revision_id != rev:
            raise PlanStoreError(
                "invalid plan pointer: revision path mismatch",
                code="invalid_plan_pointer",
            )
        inventory = self._load_inventory_file(inv_path)
        return PlanRevisionSnapshot(
            plan=plan,
            effective_inventory=inventory,
            plan_path=plan_path,
            inventory_path=inv_path,
        )

    def _publish_existing_or_raise(
        self,
        *,
        rev: str,
        candidate_plan: AuditPlan,
        candidate_inventory: ClientInventory,
        make_latest: bool,
    ) -> PlanRevisionSnapshot:
        existing = self._snapshot_from_revision_dir(rev)
        if not _same_semantic_revision(
            existing.plan,
            existing.effective_inventory,
            candidate_plan,
            candidate_inventory,
        ):
            raise PlanStoreError(
                "plan revision collision: semantic content differs",
                code="plan_revision_collision",
            )
        if make_latest:
            self._publish_latest_unlocked(existing.plan, existing.effective_inventory)
        return existing

    def _publish_new_revision_dir(
        self,
        *,
        rev: str,
        plan: AuditPlan,
        effective_inventory: ClientInventory,
    ) -> PlanRevisionSnapshot:
        final_dir = self.revision_dir(rev)
        self.revisions_dir.mkdir(parents=True, exist_ok=True)
        temp_dir = Path(
            tempfile.mkdtemp(
                prefix=f".{rev}.",
                suffix=".tmp",
                dir=str(self.revisions_dir),
            )
        )
        plan_path = temp_dir / "plan.json"
        inv_path = temp_dir / EFFECTIVE_INVENTORY_FILENAME
        try:
            plan_path.write_text(
                _canonical_json(plan.model_dump()),
                encoding="utf-8",
            )
            inv_path.write_text(
                _canonical_json(_safe_inventory_dump(effective_inventory)),
                encoding="utf-8",
            )
            _fsync_file(plan_path)
            _fsync_file(inv_path)
            _fsync_dir(temp_dir)

            if final_dir.exists():
                _rmtree_quiet(temp_dir)
                return self._publish_existing_or_raise(
                    rev=rev,
                    candidate_plan=plan,
                    candidate_inventory=effective_inventory,
                    make_latest=False,
                )

            # Never os.replace directories — rename must fail if destination exists.
            os.rename(temp_dir, final_dir)
            _fsync_dir(self.revisions_dir)
        except Exception:
            _rmtree_quiet(temp_dir)
            raise

        return PlanRevisionSnapshot(
            plan=plan,
            effective_inventory=effective_inventory,
            plan_path=self.revision_plan_path(rev),
            inventory_path=self.revision_inventory_path(rev),
        )

    def _stage_text(self, destination: Path, text: str) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        return tmp_path

    def _cleanup_tmp_files(self) -> None:
        for leftover in self.root.glob(".*.tmp"):
            try:
                leftover.unlink(missing_ok=True)
            except OSError:
                pass
        if self.revisions_dir.is_dir():
            for leftover in self.revisions_dir.glob(".*.tmp"):
                if leftover.is_dir():
                    _rmtree_quiet(leftover)
                else:
                    try:
                        leftover.unlink(missing_ok=True)
                    except OSError:
                        pass

    def _publish_latest_unlocked(
        self,
        plan: AuditPlan,
        effective_inventory: ClientInventory,
    ) -> None:
        """Publish compatibility views; pointer is the commit marker (written last)."""
        pointer = self._pointer_from_plan(plan)
        plan_text = _canonical_json(plan.model_dump())
        inv_text = _canonical_json(_safe_inventory_dump(effective_inventory))
        pointer_text = _canonical_json(pointer.to_dict())

        prev_pointer = _read_bytes_or_none(self.pointer_path)
        prev_latest = _read_bytes_or_none(self.latest_plan_path)
        prev_inventory = _read_bytes_or_none(self.latest_inventory_path)

        tmp_latest = self._stage_text(self.latest_plan_path, plan_text)
        tmp_inv = self._stage_text(self.latest_inventory_path, inv_text)
        tmp_pointer = self._stage_text(self.pointer_path, pointer_text)
        pending = [tmp_latest, tmp_inv, tmp_pointer]
        try:
            # Commit order: compatibility files first, pointer last.
            os.replace(tmp_latest, self.latest_plan_path)
            pending.remove(tmp_latest)

            os.replace(tmp_inv, self.latest_inventory_path)
            pending.remove(tmp_inv)

            os.replace(tmp_pointer, self.pointer_path)
            pending.remove(tmp_pointer)
        except Exception:
            _restore_bytes(self.latest_plan_path, prev_latest)
            _restore_bytes(self.latest_inventory_path, prev_inventory)
            _restore_bytes(self.pointer_path, prev_pointer)
            for tmp in pending:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
            self._cleanup_tmp_files()
            raise

    def persist_revision(
        self,
        plan: AuditPlan,
        effective_inventory: ClientInventory,
        *,
        make_latest: bool = True,
    ) -> PlanRevisionSnapshot:
        """Write an immutable revision and optionally advance the latest pointer."""
        rev = validate_plan_revision_id(plan.plan_revision_id or "")

        with self._exclusive_lock():
            final_dir = self.revision_dir(rev)
            if final_dir.exists():
                return self._publish_existing_or_raise(
                    rev=rev,
                    candidate_plan=plan,
                    candidate_inventory=effective_inventory,
                    make_latest=make_latest,
                )

            snapshot = self._publish_new_revision_dir(
                rev=rev,
                plan=plan,
                effective_inventory=effective_inventory,
            )
            if make_latest:
                self._publish_latest_unlocked(
                    snapshot.plan,
                    snapshot.effective_inventory,
                )
            return snapshot

    def load_revision(self, plan_revision_id: str) -> PlanRevisionSnapshot:
        rev = validate_plan_revision_id(plan_revision_id)
        return self._snapshot_from_revision_dir(rev)

    def current_revision_id(self) -> str | None:
        with self._exclusive_lock():
            pointer = self._read_pointer_unlocked()
            return None if pointer is None else pointer.plan_revision_id

    def assert_current(self, expected_plan_revision_id: str) -> None:
        expected = validate_plan_revision_id(expected_plan_revision_id)
        with self._exclusive_lock():
            self._assert_current_unlocked(expected)

    def _assert_current_unlocked(self, expected_plan_revision_id: str) -> None:
        expected = validate_plan_revision_id(expected_plan_revision_id)
        pointer = self._read_pointer_unlocked()
        if pointer is None:
            if self.latest_plan_path.is_file():
                latest = self._load_plan_file(self.latest_plan_path)
                if latest.plan_revision_id == expected:
                    return
            raise PlanStoreError(
                "audit plan revision is stale: latest pointer missing",
                code="audit_plan_stale",
            )
        if pointer.plan_revision_id != expected:
            raise PlanStoreError(
                (
                    "audit plan revision is stale: "
                    f"expected {expected!r}, "
                    f"current {pointer.plan_revision_id!r}"
                ),
                code="audit_plan_stale",
            )
        snapshot = self._snapshot_from_revision_dir(expected)
        if snapshot.plan.plan_id != pointer.plan_id:
            raise PlanStoreError(
                "invalid plan pointer: plan ID mismatch",
                code="invalid_plan_pointer",
            )

    def load_latest(self) -> PlanRevisionSnapshot:
        with self._exclusive_lock():
            pointer = self._read_pointer_unlocked()
            if pointer is not None:
                snapshot = self._snapshot_from_revision_dir(pointer.plan_revision_id)
                if snapshot.plan.plan_id != pointer.plan_id:
                    raise PlanStoreError(
                        "invalid plan pointer: plan ID mismatch",
                        code="invalid_plan_pointer",
                    )
                return snapshot
            if self.latest_plan_path.is_file():
                plan = self._load_plan_file(self.latest_plan_path)
                if plan.plan_revision_id:
                    try:
                        rev = validate_plan_revision_id(plan.plan_revision_id)
                    except PlanStoreError:
                        rev = ""
                    if rev and self.revision_plan_path(rev).is_file():
                        return self._snapshot_from_revision_dir(rev)
                if self.latest_inventory_path.is_file():
                    inventory = self._load_inventory_file(self.latest_inventory_path)
                    return PlanRevisionSnapshot(
                        plan=plan,
                        effective_inventory=inventory,
                        plan_path=self.latest_plan_path,
                        inventory_path=self.latest_inventory_path,
                    )
            raise PlanStoreError(
                "plan revision not found",
                code="plan_revision_not_found",
            )

    def persist_latest_materialized_plan(
        self,
        plan: AuditPlan,
        *,
        expected_plan_revision_id: str,
    ) -> Path:
        """Materialize confirmation/rejection into compatibility ``latest.json``.

        Never mutates immutable revision files. Pointer remains on the analysis
        revision (INPUT005-19 will introduce derived revisions for adjustments).
        """
        expected = validate_plan_revision_id(expected_plan_revision_id)
        with self._exclusive_lock():
            self._assert_current_unlocked(expected)
            if plan.plan_revision_id != expected:
                raise PlanStoreError(
                    (
                        "audit plan revision is stale: "
                        f"expected {expected!r}, current {plan.plan_revision_id!r}"
                    ),
                    code="audit_plan_stale",
                )
            text = _canonical_json(plan.model_dump())
            _atomic_write_text(self.latest_plan_path, text)
            return self.latest_plan_path

    def claim_current_revision(
        self,
        expected_plan_revision_id: str,
        *,
        materialize_plan: AuditPlan | None = None,
    ) -> PlanRevisionSnapshot:
        """Under lock: verify revision is current and optionally materialize plan."""
        expected = validate_plan_revision_id(expected_plan_revision_id)
        with self._exclusive_lock():
            self._assert_current_unlocked(expected)
            snapshot = self._snapshot_from_revision_dir(expected)
            if materialize_plan is not None:
                if materialize_plan.plan_revision_id != expected:
                    raise PlanStoreError(
                        (
                            "audit plan revision is stale: "
                            f"expected {expected!r}, "
                            f"current {materialize_plan.plan_revision_id!r}"
                        ),
                        code="audit_plan_stale",
                    )
                _atomic_write_text(
                    self.latest_plan_path,
                    _canonical_json(materialize_plan.model_dump()),
                )
            return snapshot


def find_client_for_plan_revision(
    inventory_root: Path | str,
    *,
    plan_id: str,
    plan_revision_id: str,
) -> tuple[str, Path]:
    """Locate ``{client}/.audit_plans`` for an immutable revision + plan_id."""
    root = Path(inventory_root)
    rev = validate_plan_revision_id(plan_revision_id)
    if not root.is_dir():
        raise PlanStoreError(
            "plan revision not found",
            code="plan_revision_not_found",
        )
    for client_dir in sorted(root.iterdir()):
        if not client_dir.is_dir():
            continue
        plans_root = client_dir / ".audit_plans"
        plan_path = plans_root / REVISIONS_DIRNAME / rev / "plan.json"
        if not plan_path.is_file():
            continue
        try:
            data = json.loads(plan_path.read_text(encoding="utf-8"))
            plan = AuditPlan.model_validate(data)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if plan.plan_id == plan_id and plan.plan_revision_id == rev:
            return client_dir.name, plans_root
    raise PlanStoreError(
        "plan revision not found",
        code="plan_revision_not_found",
    )


__all__ = [
    "EFFECTIVE_INVENTORY_FILENAME",
    "LatestPointer",
    "POINTER_SCHEMA_VERSION",
    "PlanRevisionSnapshot",
    "PlanRevisionStore",
    "PlanStoreError",
    "find_client_for_plan_revision",
    "validate_plan_revision_id",
]

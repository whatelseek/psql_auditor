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


def _is_safe_relative(path_text: str) -> bool:
    if not path_text or path_text.startswith(("/", "\\")):
        return False
    parts = Path(path_text).parts
    if any(part in {"", ".", ".."} for part in parts):
        return False
    # Reject drive / UNC style absolute paths on other platforms.
    if Path(path_text).is_absolute():
        return False
    return True


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
        return self.revisions_dir / plan_revision_id

    def revision_plan_path(self, plan_revision_id: str) -> Path:
        return self.revision_dir(plan_revision_id) / "plan.json"

    def revision_inventory_path(self, plan_revision_id: str) -> Path:
        return self.revision_dir(plan_revision_id) / EFFECTIVE_INVENTORY_FILENAME

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - non-POSIX
            raise PlanStoreError(
                "plan store lock unavailable: fcntl is required",
                code="plan_store_lock_failed",
            ) from exc

        lock_file = open(self.lock_path, "a+", encoding="utf-8")
        try:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            except OSError as exc:
                raise PlanStoreError(
                    "plan store lock unavailable",
                    code="plan_store_lock_failed",
                ) from exc
            yield
        finally:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            lock_file.close()

    def _write_immutable_file(self, path: Path, text: str) -> None:
        if path.is_file():
            existing = path.read_text(encoding="utf-8")
            if existing == text:
                return
            raise PlanStoreError(
                "plan revision collision: immutable content differs",
                code="plan_revision_collision",
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(path, text)
        # Re-check for a race that wrote different content under the same id.
        written = path.read_text(encoding="utf-8")
        if written != text:
            raise PlanStoreError(
                "plan revision collision: immutable content differs",
                code="plan_revision_collision",
            )

    def _pointer_from_plan(self, plan: AuditPlan) -> LatestPointer:
        rev = plan.plan_revision_id.strip()
        if not rev:
            raise PlanStoreError(
                "plan_revision_id is required to persist a revision",
                code="invalid_plan_pointer",
            )
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
        if not plan_id or not plan_revision_id:
            raise PlanStoreError(
                "invalid plan pointer: missing identifiers",
                code="invalid_plan_pointer",
            )
        if not _is_safe_relative(plan_path) or not _is_safe_relative(inv_path):
            raise PlanStoreError(
                "invalid plan pointer: unsafe path",
                code="invalid_plan_pointer",
            )
        expected_plan = f"{REVISIONS_DIRNAME}/{plan_revision_id}/plan.json"
        expected_inv = f"{REVISIONS_DIRNAME}/{plan_revision_id}/{EFFECTIVE_INVENTORY_FILENAME}"
        if plan_path != expected_plan or inv_path != expected_inv:
            raise PlanStoreError(
                "invalid plan pointer: revision path mismatch",
                code="invalid_plan_pointer",
            )
        return LatestPointer(
            schema_version=schema,
            plan_id=plan_id,
            plan_revision_id=plan_revision_id,
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

    def persist_revision(
        self,
        plan: AuditPlan,
        effective_inventory: ClientInventory,
        *,
        make_latest: bool = True,
    ) -> PlanRevisionSnapshot:
        """Write an immutable revision and optionally advance the latest pointer."""
        rev = (plan.plan_revision_id or "").strip()
        if not rev:
            raise PlanStoreError(
                "plan_revision_id is required to persist a revision",
                code="invalid_plan_pointer",
            )

        plan_text = _canonical_json(plan.model_dump())
        inv_text = _canonical_json(_safe_inventory_dump(effective_inventory))
        plan_path = self.revision_plan_path(rev)
        inv_path = self.revision_inventory_path(rev)

        # Immutable files first (outside latest-pointer critical section).
        self._write_immutable_file(plan_path, plan_text)
        self._write_immutable_file(inv_path, inv_text)

        snapshot = PlanRevisionSnapshot(
            plan=plan,
            effective_inventory=effective_inventory,
            plan_path=plan_path,
            inventory_path=inv_path,
        )
        if make_latest:
            with self._exclusive_lock():
                pointer = self._pointer_from_plan(plan)
                _atomic_write_text(
                    self.pointer_path,
                    _canonical_json(pointer.to_dict()),
                )
                _atomic_write_text(self.latest_plan_path, plan_text)
                _atomic_write_text(self.latest_inventory_path, inv_text)
        return snapshot

    def load_revision(self, plan_revision_id: str) -> PlanRevisionSnapshot:
        rev = plan_revision_id.strip()
        if not rev:
            raise PlanStoreError(
                "plan revision not found",
                code="plan_revision_not_found",
            )
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

    def current_revision_id(self) -> str | None:
        with self._exclusive_lock():
            pointer = self._read_pointer_unlocked()
            return None if pointer is None else pointer.plan_revision_id

    def assert_current(self, expected_plan_revision_id: str) -> None:
        expected = expected_plan_revision_id.strip()
        if not expected:
            raise PlanStoreError(
                "plan_revision_id is required",
                code="audit_plan_stale",
            )
        with self._exclusive_lock():
            self._assert_current_unlocked(expected)

    def _assert_current_unlocked(self, expected_plan_revision_id: str) -> None:
        pointer = self._read_pointer_unlocked()
        if pointer is None:
            # Compatibility: fall back to latest.json revision when pointer missing.
            if self.latest_plan_path.is_file():
                latest = self._load_plan_file(self.latest_plan_path)
                if latest.plan_revision_id == expected_plan_revision_id:
                    return
            raise PlanStoreError(
                "audit plan revision is stale: latest pointer missing",
                code="audit_plan_stale",
            )
        if pointer.plan_revision_id != expected_plan_revision_id:
            raise PlanStoreError(
                (
                    "audit plan revision is stale: "
                    f"expected {expected_plan_revision_id!r}, "
                    f"current {pointer.plan_revision_id!r}"
                ),
                code="audit_plan_stale",
            )
        # Fail closed if pointer paths / plan IDs disagree with on-disk revision.
        snapshot = self.load_revision(expected_plan_revision_id)
        if snapshot.plan.plan_id != pointer.plan_id:
            raise PlanStoreError(
                "invalid plan pointer: plan ID mismatch",
                code="invalid_plan_pointer",
            )

    def load_latest(self) -> PlanRevisionSnapshot:
        with self._exclusive_lock():
            pointer = self._read_pointer_unlocked()
            if pointer is not None:
                snapshot = self.load_revision(pointer.plan_revision_id)
                if snapshot.plan.plan_id != pointer.plan_id:
                    raise PlanStoreError(
                        "invalid plan pointer: plan ID mismatch",
                        code="invalid_plan_pointer",
                    )
                return snapshot
            # Compatibility bootstrap: latest.json / pointer-less trees.
            if self.latest_plan_path.is_file():
                plan = self._load_plan_file(self.latest_plan_path)
                if (
                    plan.plan_revision_id
                    and self.revision_plan_path(plan.plan_revision_id).is_file()
                ):
                    return self.load_revision(plan.plan_revision_id)
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
        expected = expected_plan_revision_id.strip()
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
        expected = expected_plan_revision_id.strip()
        with self._exclusive_lock():
            self._assert_current_unlocked(expected)
            snapshot = self.load_revision(expected)
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
    rev = plan_revision_id.strip()
    if not root.is_dir() or not rev:
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
]

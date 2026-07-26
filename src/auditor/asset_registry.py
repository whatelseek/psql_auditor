"""Stable asset identity across audit runs (CORE-003).

``asset_id`` is a durable UUID per client inventory label (or explicit id).
SSH host / IP is stored as an attribute and may change without changing
``asset_id``.
"""

from __future__ import annotations

import re
import sqlite3
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from auditor.domain.result_identity import IncompleteResultIdentityError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id        TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    inventory_key   TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    ssh_host        TEXT NOT NULL DEFAULT '',
    hostname        TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (client_id, inventory_key)
);
"""


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _slug(text: str) -> str:
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", (text or "").strip()).strip("._-")
    return raw.lower()


class AssetRegistry:
    """SQLite registry of stable ``asset_id`` values per client."""

    def __init__(self, db_path: Path | str) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._lock:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
                conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_asset(
        self,
        *,
        client_id: str,
        inventory_key: str = "",
        label: str = "",
        ssh_host: str = "",
        hostname: str = "",
        asset_id: str | None = None,
    ) -> str:
        """Return a stable asset_id; update IP/hostname attributes when known.

        ``inventory_key`` (preferred) or ``label`` identifies the asset across
        runs. IP-only identity is rejected when neither key nor label is set.
        """
        client = (client_id or "").strip()
        if not client:
            raise IncompleteResultIdentityError("client_id is required to resolve asset_id")
        key = (inventory_key or label or "").strip()
        if not key:
            raise IncompleteResultIdentityError(
                "asset_id requires a stable inventory_key or label; "
                "IP address alone is not a valid asset identity"
            )
        inv_key = _slug(key)
        if not inv_key:
            raise IncompleteResultIdentityError(
                "asset inventory_key/label produced an empty stable key"
            )
        now = _utcnow()
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT asset_id FROM assets
                    WHERE client_id = ? AND inventory_key = ?
                    """,
                    (client, inv_key),
                ).fetchone()
                if row:
                    aid = str(row["asset_id"])
                    conn.execute(
                        """
                        UPDATE assets SET
                            label = COALESCE(NULLIF(?, ''), label),
                            ssh_host = COALESCE(NULLIF(?, ''), ssh_host),
                            hostname = COALESCE(NULLIF(?, ''), hostname),
                            updated_at = ?
                        WHERE asset_id = ?
                        """,
                        (label, ssh_host, hostname, now, aid),
                    )
                    conn.commit()
                    return aid
                aid = (asset_id or "").strip() or f"asset_{uuid4().hex}"
                conn.execute(
                    """
                    INSERT INTO assets (
                        asset_id, client_id, inventory_key, label,
                        ssh_host, hostname, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        aid,
                        client,
                        inv_key,
                        label or key,
                        ssh_host or "",
                        hostname or "",
                        now,
                        now,
                    ),
                )
                conn.commit()
                return aid

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE asset_id = ?",
                    (asset_id,),
                ).fetchone()
        return dict(row) if row else None


def asset_registry_path(evidence_dir: Path | str) -> Path:
    return Path(evidence_dir) / ".asset_registry.sqlite"


def get_asset_registry(evidence_dir: Path | str) -> AssetRegistry:
    return AssetRegistry(asset_registry_path(evidence_dir))

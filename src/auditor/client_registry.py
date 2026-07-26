"""Persistent client identity (CORE-001).

``client_id`` is a stable opaque id reused across audits. Display name and
slug are configuration/path helpers only — never run identifiers.
"""

from __future__ import annotations

import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id       TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL DEFAULT '',
    slug            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (slug)
);

CREATE INDEX IF NOT EXISTS clients_slug_idx ON clients (slug);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_client_id() -> str:
    return f"client_{uuid4().hex[:16]}"


def _slugify(name: str) -> str:
    raw = re.sub(r"[^a-zA-Z0-9._-]+", "_", (name or "").strip()).strip("_")
    return (raw[:64] or "client").lower()


@dataclass(frozen=True, slots=True)
class Client:
    """Persistent client record."""

    client_id: str
    display_name: str
    slug: str
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "display_name": self.display_name,
            "slug": self.slug,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ClientRegistry:
    """SQLite registry of durable ``client_id`` values."""

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

    def ensure_client(
        self,
        *,
        display_name: str = "",
        slug: str = "",
        client_id: str | None = None,
    ) -> Client:
        """Return existing client by slug/id, or create a new one.

        Same slug always returns the same ``client_id`` across audits.
        """
        slug_key = _slugify(slug or display_name)
        name = (display_name or slug_key).strip()
        now = _utcnow()
        with self._lock:
            with self._connect() as conn:
                if client_id:
                    row = conn.execute(
                        "SELECT * FROM clients WHERE client_id = ?",
                        (client_id,),
                    ).fetchone()
                    if row:
                        conn.execute(
                            """
                            UPDATE clients SET
                                display_name = COALESCE(NULLIF(?, ''), display_name),
                                updated_at = ?
                            WHERE client_id = ?
                            """,
                            (name, now, client_id),
                        )
                        conn.commit()
                        return self._row(
                            conn.execute(
                                "SELECT * FROM clients WHERE client_id = ?",
                                (client_id,),
                            ).fetchone()
                        )
                row = conn.execute(
                    "SELECT * FROM clients WHERE slug = ?",
                    (slug_key,),
                ).fetchone()
                if row:
                    conn.execute(
                        """
                        UPDATE clients SET
                            display_name = COALESCE(NULLIF(?, ''), display_name),
                            updated_at = ?
                        WHERE slug = ?
                        """,
                        (name, now, slug_key),
                    )
                    conn.commit()
                    return self._row(
                        conn.execute(
                            "SELECT * FROM clients WHERE slug = ?",
                            (slug_key,),
                        ).fetchone()
                    )
                cid = (client_id or "").strip() or new_client_id()
                conn.execute(
                    """
                    INSERT INTO clients (
                        client_id, display_name, slug, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (cid, name, slug_key, now, now),
                )
                conn.commit()
                return Client(
                    client_id=cid,
                    display_name=name,
                    slug=slug_key,
                    created_at=now,
                    updated_at=now,
                )

    def get(self, client_id: str) -> Client | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM clients WHERE client_id = ?",
                    (client_id,),
                ).fetchone()
        return self._row(row) if row else None

    def get_by_slug(self, slug: str) -> Client | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM clients WHERE slug = ?",
                    (_slugify(slug),),
                ).fetchone()
        return self._row(row) if row else None

    @staticmethod
    def _row(row: sqlite3.Row) -> Client:
        return Client(
            client_id=str(row["client_id"]),
            display_name=str(row["display_name"] or ""),
            slug=str(row["slug"] or ""),
            created_at=str(row["created_at"] or ""),
            updated_at=str(row["updated_at"] or ""),
        )


def client_registry_path(evidence_dir: Path | str) -> Path:
    return Path(evidence_dir) / ".client_registry.sqlite"


def get_client_registry(evidence_dir: Path | str) -> ClientRegistry:
    return ClientRegistry(client_registry_path(evidence_dir))


def looks_like_audit_run_id(value: str) -> bool:
    """True when ``value`` looks like a business AuditRun id (not a client slug)."""
    text = (value or "").strip()
    return text.startswith("arun_") and len(text) > 8


def looks_like_client_id(value: str) -> bool:
    text = (value or "").strip()
    return text.startswith("client_") and len(text) > 8

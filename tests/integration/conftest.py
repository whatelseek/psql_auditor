"""Isolated disposable PostgreSQL for integration tests.

Requires ``AUDITOR_TEST_DATABASE_URL`` (admin DSN able to CREATE/DROP DATABASE).
CI supplies this from the workflow Postgres service. Local runs must point at
an ephemeral / disposable server — never a shared production warehouse.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from urllib.parse import urlparse, urlunparse

import asyncpg
import pytest
import pytest_asyncio

from auditor.config import Settings
from auditor.results_store import ResultsStore


def _admin_dsn() -> str:
    dsn = (os.environ.get("AUDITOR_TEST_DATABASE_URL") or "").strip()
    if not dsn:
        pytest.fail(
            "AUDITOR_TEST_DATABASE_URL is required for PostgreSQL integration tests "
            "(isolated disposable database). Refusing to use an implicit shared DSN."
        )
    return dsn


def _swap_database(dsn: str, database: str) -> str:
    parsed = urlparse(dsn)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            f"/{database}",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _maintenance_dsn(dsn: str) -> str:
    parsed = urlparse(dsn)
    name = (parsed.path or "/").lstrip("/") or "postgres"
    # Prefer connecting to 'postgres' for CREATE DATABASE privileges.
    if name and name != "postgres":
        return _swap_database(dsn, "postgres")
    return dsn


@pytest_asyncio.fixture
async def isolated_results_db() -> AsyncIterator[tuple[Settings, ResultsStore, str]]:
    """Create a unique database, migrate via ResultsStore, drop on teardown."""
    admin = _admin_dsn()
    db_name = f"aud002_{uuid.uuid4().hex[:12]}"
    maint = _maintenance_dsn(admin)
    conn = await asyncpg.connect(maint)
    try:
        await conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await conn.close()

    test_dsn = _swap_database(admin, db_name)
    settings = Settings(
        _env_file=None,
        results_db_enabled=True,
        results_database_url=test_dsn,
        results_db_per_client=False,
        results_db_name_prefix="results_",
    )
    store = ResultsStore(settings)
    # Force schema creation on first connect.
    probe = await asyncpg.connect(test_dsn)
    try:
        await store._ensure_schema(probe)  # noqa: SLF001 — intentional integration probe
    finally:
        await probe.close()

    try:
        yield settings, store, db_name
    finally:
        # Drop the disposable database so no client/run/evidence rows persist.
        cleanup = await asyncpg.connect(maint)
        try:
            await cleanup.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = $1 AND pid <> pg_backend_pid()
                """,
                db_name,
            )
            await cleanup.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            await cleanup.close()

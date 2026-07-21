"""Unit tests for the results PostgreSQL warehouse helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auditor.checklist import Requirement
from auditor.results_store import (
    ResultsStore,
    get_results_store,
    record_results_safe,
    sanitize_db_name,
)
from auditor.state import Finding


def test_sanitize_db_name_prefix_and_slug() -> None:
    assert sanitize_db_name("results_", "Acme Corp!") == "results_acme_corp"
    assert sanitize_db_name("results", "acme_corp") == "results_acme_corp"
    assert sanitize_db_name("results_", "") == "results_client"


def test_client_database_name_uses_slug() -> None:
    settings = SimpleNamespace(
        results_db_enabled=True,
        results_database_url="postgresql://u:p@h/postgres",
        results_db_per_client=True,
        results_db_name_prefix="results_",
    )
    store = ResultsStore(settings)  # type: ignore[arg-type]
    assert store.client_database_name("Test Company") == "results_test_company"


def test_get_results_store_disabled_without_url(monkeypatch: pytest.MonkeyPatch) -> None:
    import auditor.results_store as rs

    rs._STORE = None
    monkeypatch.setenv("RESULTS_DB_ENABLED", "true")
    monkeypatch.setenv("RESULTS_DATABASE_URL", "")
    from auditor.config import get_settings

    get_settings.cache_clear()
    assert get_results_store() is None
    get_settings.cache_clear()
    rs._STORE = None


def test_get_results_store_disabled_when_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    import auditor.results_store as rs

    rs._STORE = None
    monkeypatch.setenv("RESULTS_DB_ENABLED", "false")
    monkeypatch.setenv("RESULTS_DATABASE_URL", "postgresql://u:p@localhost/postgres")
    from auditor.config import get_settings

    get_settings.cache_clear()
    assert get_results_store() is None
    get_settings.cache_clear()
    rs._STORE = None


@pytest.mark.asyncio
async def test_record_results_safe_noop_when_disabled() -> None:
    settings = SimpleNamespace(
        results_db_enabled=False,
        results_database_url="",
        results_db_per_client=True,
        results_db_name_prefix="results_",
    )
    with patch("auditor.results_store.get_results_store", return_value=None):
        await record_results_safe(
            settings,  # type: ignore[arg-type]
            client_name="c",
            evidence_run_id="c",
            framework_id="ubuntu_cis",
            evidence_host_id=None,
            findings={},
        )


@pytest.mark.asyncio
async def test_record_host_framework_audit_writes_cells() -> None:
    settings = SimpleNamespace(
        results_db_enabled=True,
        results_database_url="postgresql://u:p@localhost/postgres",
        results_db_per_client=False,
        results_db_name_prefix="results_",
    )
    store = ResultsStore(settings)  # type: ignore[arg-type]
    findings = {
        "REQ-001": Finding(
            requirement_id="REQ-001",
            title="SSH root",
            category="Access",
            severity="High",
            status="fail",
            pass_criteria="PermitRootLogin no",
            evidence="PermitRootLogin yes",
            remediation="Set PermitRootLogin no",
            notes="",
        )
    }
    requirements = {
        "REQ-001": Requirement(
            id="REQ-001",
            title="SSH root",
            category="Access",
            severity="High",
            how_to_verify="sshd -T",
            pass_criteria="PermitRootLogin no",
        )
    }

    conn = MagicMock()
    conn.fetchval = AsyncMock(side_effect=[11, 22, 33])
    conn.execute = AsyncMock()
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=tx)
    conn.close = AsyncMock()

    with (
        patch.object(store, "_ensure_schema_on_dsn", new=AsyncMock()),
        patch("auditor.results_store.asyncpg.connect", new=AsyncMock(return_value=conn)),
    ):
        await store.record_host_framework_audit(
            client_name="Acme",
            evidence_run_id="Acme",
            framework_id="ubuntu_cis",
            evidence_host_id="10.0.0.1",
            findings=findings,
            requirements=requirements,
            evidence_relpath="Acme",
            source="finalize",
        )

    assert conn.fetchval.await_count == 3
    assert conn.execute.await_count >= 2
    # requirement_results insert includes observation + recommendation
    req_calls = [
        c
        for c in conn.execute.await_args_list
        if c.args and "INSERT INTO requirement_results" in str(c.args[0])
    ]
    assert req_calls
    args = req_calls[0].args
    assert "PermitRootLogin yes" in args
    assert "Set PermitRootLogin no" in args
    assert "tool stdout" not in str(args)

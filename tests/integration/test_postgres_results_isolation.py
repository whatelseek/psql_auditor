"""Genuine PostgreSQL warehouse integration (isolated disposable database)."""

from __future__ import annotations

import pytest

from auditor.checklist import Requirement
from auditor.domain.result_identity import new_result_id
from auditor.legacy_compat import MissingAuditRunIdError
from auditor.state import Finding

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_connection_and_migration_initialization(isolated_results_db) -> None:
    """Schema is applied automatically on first warehouse connect."""
    _settings, store, db_name = isolated_results_db
    assert store.enabled
    assert db_name.startswith("aud002_")
    session = await store.start_session(
        client_name="AcmeCorp",
        evidence_run_id="acmecorp/arun_integ00000001",
        audit_run_id="arun_integ00000001",
        client_id="client_integ00000001",
        framework_id="postgres_cis",
    )
    assert session is not None
    assert session.session_number == 1
    assert session.audit_run_id == "arun_integ00000001"


@pytest.mark.asyncio
async def test_create_and_retrieve_audit_scoped_record(isolated_results_db) -> None:
    """Session + requirement cells round-trip under an explicit audit_run_id."""
    _settings, store, _db = isolated_results_db
    arun = "arun_integ00000002"
    client_id = "client_integ00000002"
    session = await store.start_session(
        client_name="BetaCo",
        evidence_run_id=f"betaco/{arun}",
        audit_run_id=arun,
        client_id=client_id,
        framework_id="postgres_cis",
    )
    assert session is not None

    rid = new_result_id()
    finding = Finding(
        requirement_id="REQ-001",
        title="SCRAM auth",
        status="pass",
        severity="high",
        category="Auth",
        pass_criteria="scram-sha-256",
        evidence="password_encryption=scram-sha-256",
        remediation="",
        result_id=rid,
        client_id=client_id,
        audit_run_id=arun,
        asset_id="asset_db01",
        framework_id="postgres_cis",
        framework_version="1.0",
    )
    req = Requirement(
        id="REQ-001",
        title="SCRAM auth",
        category="Auth",
        severity="high",
        pass_criteria="scram-sha-256",
        how_to_verify="SHOW password_encryption",
    )
    await store.record_host_framework_audit(
        client_name="BetaCo",
        evidence_run_id=f"betaco/{arun}",
        framework_id="postgres_cis",
        evidence_host_id="db-01",
        findings={rid: finding},
        requirements={"REQ-001": req},
        session_number=session.session_number,
        audit_run_id=arun,
        client_id=client_id,
        source="finalize",
    )
    loaded = await store.get_session_by_audit_run(arun, client_name="BetaCo")
    assert loaded is not None
    assert loaded.audit_run_id == arun
    assert loaded.session_number == session.session_number
    _info, _hosts, reqs = await store.list_session_requirement_results(
        client_name="BetaCo",
        session_number=session.session_number,
    )
    assert any(str(r.get("req_id") or r.get("requirement_id") or "") == "REQ-001" for r in reqs)


@pytest.mark.asyncio
async def test_isolation_between_two_audit_run_ids_same_client(isolated_results_db) -> None:
    """Two runs for one client never share warehouse session identity."""
    _settings, store, _db = isolated_results_db
    client = "SharedClient"
    client_id = "client_integ00000003"
    a = await store.start_session(
        client_name=client,
        evidence_run_id="sharedclient/arun_integ0000000a",
        audit_run_id="arun_integ0000000a",
        client_id=client_id,
    )
    b = await store.start_session(
        client_name=client,
        evidence_run_id="sharedclient/arun_integ0000000b",
        audit_run_id="arun_integ0000000b",
        client_id=client_id,
    )
    assert a is not None and b is not None
    assert a.audit_run_id != b.audit_run_id
    assert a.session_number != b.session_number
    got_a = await store.get_session_by_audit_run("arun_integ0000000a", client_name=client)
    got_b = await store.get_session_by_audit_run("arun_integ0000000b", client_name=client)
    assert got_a is not None and got_b is not None
    assert got_a.session_number == a.session_number
    assert got_b.session_number == b.session_number


@pytest.mark.asyncio
async def test_reject_run_scoped_write_without_audit_run_id(isolated_results_db) -> None:
    """Warehouse session allocation requires a canonical audit_run_id."""
    _settings, store, _db = isolated_results_db
    with pytest.raises(MissingAuditRunIdError):
        await store.start_session(
            client_name="NoRun",
            evidence_run_id="norun/missing",
            audit_run_id="",
            client_id="client_integ00000004",
        )


@pytest.mark.asyncio
async def test_database_recreated_between_independent_runs(isolated_results_db) -> None:
    """Each test receives a fresh DB name; prior sessions are not visible.

    This test writes one session and asserts only that row exists in *this*
    disposable database. Cross-run isolation is enforced by unique DB names +
    DROP DATABASE in the fixture teardown (see also gate regression tests).
    """
    _settings, store, db_name = isolated_results_db
    await store.start_session(
        client_name="FreshDB",
        evidence_run_id="freshdb/arun_integ0000000c",
        audit_run_id="arun_integ0000000c",
        client_id="client_integ00000005",
    )
    sessions = await store.list_sessions(client_name="FreshDB", limit=50)
    assert len(sessions) == 1
    assert sessions[0].audit_run_id == "arun_integ0000000c"
    assert db_name.startswith("aud002_")


@pytest.mark.asyncio
async def test_two_disposable_databases_do_not_share_state(isolated_results_db) -> None:
    """Parallel-style isolation: a second disposable DB cannot see the first."""
    import os
    import uuid
    from urllib.parse import urlparse, urlunparse

    import asyncpg

    from auditor.config import Settings
    from auditor.results_store import ResultsStore

    settings_a, store_a, db_a = isolated_results_db
    await store_a.start_session(
        client_name="IsoA",
        evidence_run_id="isoa/arun_gate0000000001",
        audit_run_id="arun_gate0000000001",
        client_id="client_gate00000001",
    )

    admin = os.environ["AUDITOR_TEST_DATABASE_URL"]
    parsed = urlparse(admin)
    maint = urlunparse(
        (parsed.scheme, parsed.netloc, "/postgres", parsed.params, parsed.query, parsed.fragment)
    )
    db_b = f"aud002_{uuid.uuid4().hex[:12]}"
    conn = await asyncpg.connect(maint)
    try:
        await conn.execute(f'CREATE DATABASE "{db_b}"')
    finally:
        await conn.close()
    dsn_b = urlunparse(
        (parsed.scheme, parsed.netloc, f"/{db_b}", parsed.params, parsed.query, parsed.fragment)
    )
    store_b = ResultsStore(
        Settings(
            _env_file=None,
            results_db_enabled=True,
            results_database_url=dsn_b,
            results_db_per_client=False,
        )
    )
    try:
        sessions_b = await store_b.list_sessions(client_name="IsoA", limit=50)
        assert sessions_b == []
        assert db_a != db_b
        assert db_a in (settings_a.results_database_url or "")
    finally:
        cleanup = await asyncpg.connect(maint)
        try:
            await cleanup.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = $1 AND pid <> pg_backend_pid()
                """,
                db_b,
            )
            await cleanup.execute(f'DROP DATABASE IF EXISTS "{db_b}"')
        finally:
            await cleanup.close()

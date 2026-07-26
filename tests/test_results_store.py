"""Unit tests for the results PostgreSQL warehouse helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auditor.checklist import Requirement
from auditor.config import Settings
from auditor.intent import classify_intent
from auditor.results_store import (
    AuditSessionInfo,
    ResultsStore,
    bind_results_store,
    format_session_results_markdown,
    format_sessions_markdown,
    get_results_store,
    parse_continue_session_request,
    parse_list_results_request,
    record_results_safe,
    resolve_session_evidence,
    sanitize_db_name,
)
from auditor.state import Finding


def test_parse_continue_session_request() -> None:
    num, client = parse_continue_session_request("continue session 1 for TestCompany")
    assert num == 1
    assert client == "TestCompany"


def test_parse_list_results_request() -> None:
    client, num = parse_list_results_request("List results for AlphaCo session 2")
    assert client == "AlphaCo"
    assert num == 2
    client, num = parse_list_results_request("list-results AlphaCo 2")
    assert client == "AlphaCo"
    assert num == 2
    client, num = parse_list_results_request("Результаты для BetaCo сессия 1")
    assert client == "BetaCo"
    assert num == 1


def test_parse_list_status_and_host_request() -> None:
    from auditor.results_store import (
        format_session_status_markdown,
        parse_list_host_request,
        parse_list_status_request,
    )

    client, num = parse_list_status_request("List status for AlphaCo session 2")
    assert client == "AlphaCo"
    assert num == 2
    client, num = parse_list_status_request("list-status BetaCo 1")
    assert client == "BetaCo"
    assert num == 1

    host, fw, client = parse_list_host_request("list-host 10.200.29.79 it_audit")
    assert host == "10.200.29.79"
    assert fw == "it_audit"
    assert client is None
    host, fw, client = parse_list_host_request("list-host pg-db ubuntu_cis_24_l2 for AlphaCo")
    assert host == "pg-db"
    assert fw == "ubuntu_cis_24_l2"
    assert client == "AlphaCo"

    text = format_session_status_markdown(
        AuditSessionInfo(
            id=1,
            session_number=2,
            client_name="AlphaCo",
            client_slug="alphaco",
            evidence_run_id="AlphaCo",
            status="running",
            framework_id="it_audit",
        ),
        [
            {
                "hostname": "pg-db",
                "ip": "10.200.29.79",
                "framework_id": "it_audit",
                "ready_label": "15/60 ready",
            }
        ],
    )
    assert "15/60 ready" in text
    assert "pg-db" in text


def test_intent_list_results() -> None:
    assert classify_intent("List results for AlphaCo session 2") == "list_results"
    assert classify_intent("list-results AlphaCo 2") == "list_results"
    assert classify_intent("Show warehouse results for Acme") == "list_results"
    assert classify_intent("List status for AlphaCo session 2") == "list_status"
    assert classify_intent("list-status AlphaCo 2") == "list_status"
    assert classify_intent("list-host 10.0.0.1 it_audit") == "list_host"
    assert classify_intent("List audit sessions") == "list_sessions"


def test_format_session_results_markdown() -> None:
    text = format_session_results_markdown(
        AuditSessionInfo(
            id=1,
            session_number=2,
            client_name="AlphaCo",
            client_slug="alphaco",
            evidence_run_id="AlphaCo",
            status="completed",
            framework_id="it_audit",
        ),
        [
            {
                "host_label": "10.200.29.79",
                "framework_id": "it_audit",
                "pass_count": 4,
                "fail_count": 1,
                "partial_count": 0,
                "error_count": 2,
                "skipped_count": 0,
                "compliance_pct": 57.1,
            }
        ],
        [
            {
                "req_id": "REQ-001",
                "title": "Inventory completeness",
                "status": "pass",
                "severity": "High",
                "framework_id": "it_audit",
                "host_label": "10.200.29.79",
                "observation": "Hostname pg-server recorded",
            }
        ],
    )
    assert "session **#2**" in text
    assert "REQ-001" in text
    assert "57.1" in text


def test_resolve_session_evidence_prefers_nested_audit_run(tmp_path) -> None:
    arun = "arun_deadbeefcafebabe"
    nested = tmp_path / "testcompany" / arun
    nested.mkdir(parents=True)
    (nested / "meta.json").write_text(
        '{"thread_id":"audit-abc:10.0.0.1:ubuntu_cis_24_l2",'
        '"continue_thread_id":"audit-abc:10.0.0.1:ubuntu_cis_24_l2",'
        '"client_name":"TestCompany","audit_run_id":"arun_deadbeefcafebabe"}',
        encoding="utf-8",
    )
    # Stale temp folder left behind after rename
    (tmp_path / "20260722T043018Z_deadbeef").mkdir()

    settings = SimpleNamespace(evidence_dir=tmp_path)
    info = AuditSessionInfo(
        id=1,
        session_number=1,
        client_name="TestCompany",
        client_slug="testcompany",
        evidence_run_id="20260722T043018Z_deadbeef",
        status="running",
        continue_thread_id="audit-abc",
        audit_run_id=arun,
        client_id="client_deadbeefcafe01",
    )
    tid, run_id = resolve_session_evidence(settings, info)  # type: ignore[arg-type]
    assert run_id == f"testcompany/{arun}"
    assert tid == "audit-abc:10.0.0.1:ubuntu_cis_24_l2"


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
    monkeypatch.setenv("RESULTS_DB_ENABLED", "true")
    monkeypatch.setenv("RESULTS_DATABASE_URL", "")
    from auditor.config import get_settings

    get_settings.cache_clear()
    assert get_results_store() is None
    get_settings.cache_clear()


def test_get_results_store_disabled_when_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RESULTS_DB_ENABLED", "false")
    monkeypatch.setenv("RESULTS_DATABASE_URL", "postgresql://u:p@localhost/postgres")
    from auditor.config import get_settings

    get_settings.cache_clear()
    assert get_results_store() is None
    get_settings.cache_clear()


def test_get_results_store_context_binding() -> None:
    settings = Settings(
        _env_file=None,
        results_db_enabled=True,
        results_database_url="postgresql://u:p@h/postgres",
    )
    store = ResultsStore(settings)  # type: ignore[arg-type]
    with bind_results_store(store):
        assert get_results_store() is store
    with bind_results_store(None):
        assert get_results_store() is None


def test_intent_list_sessions() -> None:
    assert classify_intent("Which sessions need continue?") == "list_sessions"
    assert classify_intent("List audit sessions") == "list_sessions"
    assert classify_intent("Какие сессии прерваны?") == "list_sessions"
    assert classify_intent("Start Ubuntu CIS audit") == "audit"


def test_format_sessions_markdown_includes_continue_hints() -> None:
    text = format_sessions_markdown(
        [
            AuditSessionInfo(
                id=1,
                session_number=3,
                client_name="Acme",
                client_slug="acme",
                evidence_run_id="Acme",
                status="interrupted",
                continue_thread_id="user-1:ubuntu_cis",
                framework_id="ubuntu_cis",
                pending_ids=("REQ-010", "REQ-011"),
                started_at=datetime.now(timezone.utc),
            )
        ]
    )
    assert "#3" in text
    assert "Acme" in text
    assert "[AUDIT_CONTINUE:user-1:ubuntu_cis]" in text


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
            session_number=1,
        )


@pytest.mark.asyncio
async def test_start_session_allocates_next_number() -> None:
    settings = SimpleNamespace(
        results_db_enabled=True,
        results_database_url="postgresql://u:p@localhost/postgres",
        results_db_per_client=False,
        results_db_name_prefix="results_",
    )
    store = ResultsStore(settings)  # type: ignore[arg-type]

    class _Row(dict):
        def get(self, key, default=None):
            return dict.get(self, key, default)

    row = _Row(
        id=9,
        session_number=2,
        client_name="Acme",
        client_slug="acme",
        client_id="client_deadbeefcafe01",
        audit_run_id="arun_deadbeefcafebabe",
        evidence_run_id="acme/arun_deadbeefcafebabe",
        status="running",
        continue_thread_id="t1",
        framework_id="",
        pending_ids=[],
        started_at=datetime.now(timezone.utc),
        finished_at=None,
    )
    conn = MagicMock()
    conn.fetchval = AsyncMock(return_value=2)
    # First fetchrow: lookup by audit_run_id (miss); second: INSERT RETURNING
    conn.fetchrow = AsyncMock(side_effect=[None, row])
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=tx)
    conn.execute = AsyncMock()
    conn.close = AsyncMock()

    with (
        patch.object(store, "_ensure_schema_on_dsn", new=AsyncMock()),
        patch("auditor.results_store.asyncpg.connect", new=AsyncMock(return_value=conn)),
    ):
        info = await store.start_session(
            client_name="Acme",
            evidence_run_id="acme/arun_deadbeefcafebabe",
            continue_thread_id="t1",
            audit_run_id="arun_deadbeefcafebabe",
            client_id="client_deadbeefcafe01",
        )

    assert info is not None
    assert info.session_number == 2
    assert info.id == 9


@pytest.mark.asyncio
async def test_record_host_framework_audit_tags_session_number() -> None:
    settings = SimpleNamespace(
        results_db_enabled=True,
        results_database_url="postgresql://u:p@localhost/postgres",
        results_db_per_client=False,
        results_db_name_prefix="results_",
    )
    store = ResultsStore(settings)  # type: ignore[arg-type]
    findings = {
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": Finding(
            result_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            client_id="acme",
            audit_run_id="arun_test",
            asset_id="asset_host_1",
            framework_id="ubuntu_cis",
            framework_version="24.0",
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

    class _Row(dict):
        def __getitem__(self, key):
            return dict.__getitem__(self, key)

        def get(self, key, default=None):
            return dict.get(self, key, default)

    sess_row = _Row(
        id=11,
        session_number=3,
        client_name="Acme",
        client_slug="acme",
        client_id="acme",
        audit_run_id="arun_test",
        evidence_run_id="Acme",
        status="running",
        continue_thread_id="",
        framework_id="",
        pending_ids=[],
        started_at=datetime.now(timezone.utc),
        finished_at=None,
    )

    conn = MagicMock()
    conn.fetchrow = AsyncMock(side_effect=[sess_row, None, None])
    conn.fetchval = AsyncMock(side_effect=[22, 33])  # host_pk, hr_pk
    conn.execute = AsyncMock()
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=tx)
    conn.close = AsyncMock()

    with (
        patch.object(store, "_ensure_schema", new=AsyncMock()),
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
            session_number=3,
        )

    req_calls = [
        c
        for c in conn.execute.await_args_list
        if c.args and "INSERT INTO requirement_results" in str(c.args[0])
    ]
    assert req_calls
    args = req_calls[0].args
    assert 3 in args  # session_number column
    host_upsert = [
        c
        for c in conn.fetchval.await_args_list
        if c.args and "INSERT INTO host_results" in str(c.args[0])
    ]
    assert host_upsert
    assert "ON CONFLICT (session_id, host_id, framework_id)" in str(host_upsert[0].args[0])


@pytest.mark.asyncio
async def test_upsert_requirement_result_live() -> None:
    settings = SimpleNamespace(
        results_db_enabled=True,
        results_database_url="postgresql://u:p@localhost/postgres",
        results_db_per_client=False,
        results_db_name_prefix="results_",
    )
    store = ResultsStore(settings)  # type: ignore[arg-type]
    finding = Finding(
        result_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        client_id="acme",
        audit_run_id="arun_live",
        asset_id="asset_host_1",
        framework_id="it_audit",
        framework_version="1.0",
        requirement_id="REQ-002",
        title="Banner",
        category="Access",
        severity="Low",
        status="pass",
        evidence="ok",
        remediation="",
    )
    requirement = Requirement(
        id="REQ-002",
        title="Banner",
        category="Access",
        severity="Low",
        how_to_verify="cat",
        pass_criteria="present",
    )

    class _Row(dict):
        def __getitem__(self, key):
            return dict.__getitem__(self, key)

        def get(self, key, default=None):
            return dict.get(self, key, default)

    sess_row = _Row(
        id=11,
        session_number=1,
        client_name="Acme",
        client_slug="acme",
        client_id="acme",
        audit_run_id="arun_live",
        evidence_run_id="Acme",
        status="running",
        continue_thread_id="",
        framework_id="it_audit",
        pending_ids=[],
        started_at=datetime.now(timezone.utc),
        finished_at=None,
    )

    conn = MagicMock()
    conn.fetchrow = AsyncMock(side_effect=[sess_row, None, None])
    conn.fetchval = AsyncMock(side_effect=[22, 44])  # host, hr
    conn.fetch = AsyncMock(
        return_value=[
            {
                "result_id": finding.result_id,
                "req_id": "REQ-002",
                "status": "pass",
                "title": "Banner",
                "severity": "Low",
                "client_id": "acme",
                "audit_run_id": "arun_live",
                "asset_id": "asset_host_1",
                "framework_id": "it_audit",
                "framework_version": "1.0",
            }
        ]
    )
    conn.execute = AsyncMock()
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=tx)
    conn.close = AsyncMock()

    with (
        patch.object(store, "_ensure_schema", new=AsyncMock()),
        patch("auditor.results_store.asyncpg.connect", new=AsyncMock(return_value=conn)),
    ):
        await store.upsert_requirement_result(
            client_name="Acme",
            evidence_run_id="Acme",
            framework_id="it_audit",
            evidence_host_id="10.0.0.1",
            finding=finding,
            requirement=requirement,
            evidence_relpath="Acme",
            source="live",
            session_number=1,
        )

    completed = [
        c
        for c in conn.execute.await_args_list
        if c.args and "status = 'completed'" in str(c.args[0])
    ]
    assert not completed
    req_calls = [
        c
        for c in conn.execute.await_args_list
        if c.args and "INSERT INTO requirement_results" in str(c.args[0])
    ]
    assert req_calls
    refresh = [
        c
        for c in conn.execute.await_args_list
        if c.args and "UPDATE host_results SET" in str(c.args[0])
    ]
    assert refresh


@pytest.mark.asyncio
async def test_record_requirement_result_safe_forwards() -> None:
    from auditor.results_store import record_requirement_result_safe

    settings = SimpleNamespace(results_db_enabled=True)
    mock_store = MagicMock()
    mock_store.upsert_requirement_result = AsyncMock()
    with patch(
        "auditor.results_store.get_results_store",
        return_value=mock_store,
    ):
        await record_requirement_result_safe(
            settings,  # type: ignore[arg-type]
            client_name="Acme",
            evidence_run_id="Acme",
            framework_id="it_audit",
            evidence_host_id=None,
            finding=Finding(requirement_id="REQ-001", status="pass"),
        )
    mock_store.upsert_requirement_result.assert_awaited_once()

"""Tests for run-scoped SSH/PG credentials (concurrent-audit isolation)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from auditor.config import Settings
from auditor.runtime_target import (
    bind_runtime_credentials,
    effective_settings,
    get_runtime_target,
    pg_fingerprint,
)
from auditor.secrets_file import InventorySshTarget, bind_ssh_target, read_client_credentials
from auditor.tools.mcp_client import PostgresMcpSession


def test_bind_ssh_target_does_not_mutate_os_environ(monkeypatch):
    monkeypatch.setenv("SSH_HOST", "baseline.example")
    before = os.environ.get("SSH_HOST")
    target = InventorySshTarget(host="10.0.0.9", port="22", user="auditor")
    with bind_ssh_target(target):
        assert os.environ.get("SSH_HOST") == before
        assert effective_settings(
            Settings(_env_file=None, ssh_host="baseline.example")
        ).ssh_host == "10.0.0.9"
        assert effective_settings(
            Settings(_env_file=None, ssh_host="baseline.example")
        ).ssh_user == "auditor"
    assert get_runtime_target() is None
    assert os.environ.get("SSH_HOST") == before


def test_bind_ssh_target_environ_dict_still_mutates():
    env: dict[str, str] = {"SSH_HOST": "old"}
    target = InventorySshTarget(host="10.1.1.1", port="2222", user="u", password="p")
    with bind_ssh_target(target, environ=env):
        assert env["SSH_HOST"] == "10.1.1.1"
        assert env["SSH_PORT"] == "2222"
        assert env["SSH_USER"] == "u"
        assert env["SSH_PASSWORD"] == "p"
        # ContextVar path not used when environ= is passed
        assert get_runtime_target() is None
    assert env["SSH_HOST"] == "old"
    assert "SSH_PASSWORD" not in env


def test_nested_ssh_keeps_pg_overlay():
    base = Settings(
        _env_file=None,
        ssh_host="default",
        pg_host="pg-default",
        pg_password="secret",
    )
    with bind_runtime_credentials(
        {"PG_HOST": "db.client-a", "PG_PASSWORD": "a-pass", "PG_DATABASE": "a"}
    ):
        assert effective_settings(base).pg_host == "db.client-a"
        with bind_ssh_target(
            InventorySshTarget(host="ssh.client-a", user="root", password="ssh-a")
        ):
            eff = effective_settings(base)
            assert eff.ssh_host == "ssh.client-a"
            assert eff.ssh_password == "ssh-a"
            assert eff.pg_host == "db.client-a"
            assert eff.pg_password == "a-pass"
            assert eff.pg_database == "a"
        # SSH overlay cleared; PG remains
        assert effective_settings(base).ssh_host == "default"
        assert effective_settings(base).pg_host == "db.client-a"


@pytest.mark.asyncio
async def test_concurrent_binds_do_not_clobber():
    base = Settings(_env_file=None, ssh_host="baseline", pg_host="pg-base")
    seen: dict[str, str] = {}
    barrier = asyncio.Barrier(2)

    async def worker(name: str, host: str, pg: str) -> None:
        with bind_runtime_credentials({"SSH_HOST": host, "PG_HOST": pg}):
            await barrier.wait()
            await asyncio.sleep(0.02)
            eff = effective_settings(base)
            seen[name] = f"{eff.ssh_host}|{eff.pg_host}"
            await barrier.wait()

    await asyncio.gather(
        worker("a", "host-a", "pg-a"),
        worker("b", "host-b", "pg-b"),
    )
    assert seen["a"] == "host-a|pg-a"
    assert seen["b"] == "host-b|pg-b"
    assert get_runtime_target() is None


def test_read_client_credentials_no_env_mutation(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SSH_HOST", "keep-me")
    client = tmp_path / "Acme"
    client.mkdir()
    (client / "INVENTORY.md").write_text(
        """
| Access | Host / URL | Port | Username | Password / Token | Database |
|--------|------------|------|----------|------------------|----------|
| SSH | 10.9.9.9 | 22 | auditor | | |
| PostgreSQL | 10.9.9.9 | 5432 | pg | secret | app |
""",
        encoding="utf-8",
    )
    applied = read_client_credentials(tmp_path, "acme")
    assert applied["SSH_HOST"] == "10.9.9.9"
    assert applied["PG_PASSWORD"] == "secret"
    assert os.environ.get("SSH_HOST") == "keep-me"


@pytest.mark.asyncio
async def test_mcp_session_recycles_on_pg_fingerprint_change():
    session = PostgresMcpSession()
    settings_a = Settings(
        _env_file=None,
        pg_host="db-a",
        pg_user="u",
        pg_password="p",
        pg_database="a",
    )
    settings_b = Settings(
        _env_file=None,
        pg_host="db-b",
        pg_user="u",
        pg_password="p",
        pg_database="b",
    )
    assert pg_fingerprint(settings_a) != pg_fingerprint(settings_b)

    builds: list[str] = []
    fake_remote = AsyncMock()
    fake_remote.call_tool = AsyncMock(
        return_value=type("R", (), {"content": [], "isError": False})()
    )

    class _FakeStack:
        async def aclose(self):
            return None

        async def enter_async_context(self, cm):
            return fake_remote

    def build_client(settings):
        builds.append(pg_fingerprint(settings))
        client = AsyncMock()
        client.session = lambda *a, **k: object()
        return client

    session._build_client = build_client  # type: ignore[method-assign]

    # Patch AsyncExitStack used inside _ensure_session
    import auditor.tools.mcp_client as mcp_mod

    real_stack = mcp_mod.AsyncExitStack

    def stack_factory():
        return _FakeStack()

    mcp_mod.AsyncExitStack = stack_factory  # type: ignore[misc,assignment]
    try:
        await session.call_tool("query", {"sql": "SELECT 1"}, settings=settings_a)
        await session.call_tool("query", {"sql": "SELECT 1"}, settings=settings_a)
        await session.call_tool("query", {"sql": "SELECT 1"}, settings=settings_b)
    finally:
        mcp_mod.AsyncExitStack = real_stack

    assert len(builds) == 2
    assert builds[0] == pg_fingerprint(settings_a)
    assert builds[1] == pg_fingerprint(settings_b)

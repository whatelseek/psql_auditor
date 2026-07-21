"""Tests for Postgres MCP session pool concurrency."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from auditor.config import Settings
from auditor.tools.mcp_client import PostgresMcpPool, PostgresMcpSession


@pytest.mark.asyncio
async def test_pool_runs_calls_concurrently():
    pool = PostgresMcpPool(size=3)
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def slow_call(tool_name, arguments=None, settings=None):
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        return f"ok:{tool_name}"

    settings = Settings(_env_file=None, mcp_postgres_pool_size=3)
    await pool._ensure(settings)
    for session in pool._sessions:
        session.call_tool = slow_call  # type: ignore[method-assign]

    results = await asyncio.gather(
        *[pool.call_tool("query", {"sql": f"SELECT {i}"}) for i in range(3)]
    )
    assert results == ["ok:query", "ok:query", "ok:query"]
    assert max_in_flight >= 3
    assert pool.size == 3
    await pool.close()


@pytest.mark.asyncio
async def test_pool_reconnect_all_workers():
    pool = PostgresMcpPool(size=2)
    settings = Settings(_env_file=None, mcp_postgres_pool_size=2)
    await pool._ensure(settings)
    for session in pool._sessions:
        session.reconnect = AsyncMock(
            return_value="MCP session reconnected successfully"
        )
    status = await pool.reconnect(settings)
    assert "2 workers" in status
    for session in pool._sessions:
        session.reconnect.assert_awaited()
    await pool.close()


def test_pool_size_clamped():
    settings = Settings(_env_file=None, mcp_postgres_pool_size=100)
    pool = PostgresMcpPool()
    assert pool._resolve_size(settings) == 16
    settings2 = Settings(_env_file=None, mcp_postgres_pool_size=0)
    assert pool._resolve_size(settings2) == 1

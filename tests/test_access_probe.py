"""Tests for generic intake access probing."""

import asyncio

import pytest

from auditor.access_probe import probe_access_endpoints, probe_tcp_endpoint


@pytest.mark.asyncio
async def test_probe_tcp_endpoint_success():
    async def _handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        del reader
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_handler, host="127.0.0.1", port=0)
    try:
        port = server.sockets[0].getsockname()[1]
        assert await probe_tcp_endpoint("127.0.0.1", str(port), timeout=1.0) is True
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_probe_access_endpoints_generic_and_missing_port():
    async def _handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await asyncio.wait_for(reader.read(512), timeout=0.2)
        except TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_handler, host="127.0.0.1", port=0)
    try:
        port = str(server.sockets[0].getsockname()[1])
        rows = await probe_access_endpoints(
            [
                {
                    "service": "Legacy App",
                    "host": "127.0.0.1",
                    "port": port,
                    "kind": "tcp",
                    "protocol": "tcp",
                },
                {
                    "service": "Broken endpoint",
                    "host": "127.0.0.1",
                    "port": "",
                    "kind": "tcp",
                    "protocol": "tcp",
                },
            ],
            timeout=1.0,
        )
    finally:
        server.close()
        await server.wait_closed()

    assert rows[0]["status"] == "accessible"
    assert rows[0]["detail"] == ""
    assert rows[1]["status"] == "unknown"
    assert "missing port" in rows[1]["detail"]


@pytest.mark.asyncio
async def test_probe_access_endpoints_snmp_uses_tcp_reachability():
    async def _handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        del reader
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_handler, host="127.0.0.1", port=0)
    try:
        port = str(server.sockets[0].getsockname()[1])
        rows = await probe_access_endpoints(
            [
                {
                    "service": "SNMP endpoint",
                    "host": "127.0.0.1",
                    "port": port,
                    "kind": "snmp",
                    "protocol": "snmp",
                }
            ],
            timeout=1.0,
        )
    finally:
        server.close()
        await server.wait_closed()

    assert rows[0]["status"] == "accessible"
    assert rows[0]["detail"] == "tcp probe on SNMP port"

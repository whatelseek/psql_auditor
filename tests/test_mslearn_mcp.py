"""Tests for Microsoft Learn remote MCP tool wrappers."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auditor.tools import mslearn_mcp


@pytest.mark.asyncio
async def test_microsoft_docs_search_calls_remote_tool():
    session = AsyncMock()
    session.call_tool = AsyncMock(
        return_value=MagicMock(
            content=[MagicMock(text='{"results":[{"title":"WinRM"}]}')],
            isError=False,
        )
    )
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    client = MagicMock()
    client.session = MagicMock(return_value=session)

    with (
        patch.object(
            mslearn_mcp,
            "microsoft_learn_mcp_connection",
            return_value={
                "transport": "streamable_http",
                "url": "https://learn.microsoft.com/api/mcp",
            },
        ),
        patch.object(mslearn_mcp, "MultiServerMCPClient", return_value=client),
    ):
        text = await mslearn_mcp.microsoft_docs_search.ainvoke({"query": "enable WinRM"})

    assert "WinRM" in text
    session.call_tool.assert_awaited_once_with(
        "microsoft_docs_search",
        arguments={"query": "enable WinRM"},
    )


@pytest.mark.asyncio
async def test_microsoft_docs_search_disabled_message():
    with patch.object(mslearn_mcp, "microsoft_learn_mcp_connection", return_value=None):
        text = await mslearn_mcp.microsoft_docs_search.ainvoke({"query": "x"})
    assert "disabled" in text.lower() or "missing" in text.lower()

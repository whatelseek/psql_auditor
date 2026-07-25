"""Microsoft Learn remote MCP tools (docs / code samples).

Uses the public Streamable HTTP endpoint from
https://github.com/microsoftdocs/mcp — no API key. Bound into the assess
toolset so the model can look up official how-to guidance before inventing
commands (especially Windows / Azure / .NET / PowerShell / WinRM).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient

from auditor.mcp_registry import (
    build_http_connection,
    load_mcp_registry,
)
from auditor.runtime_target import effective_settings
from auditor.tools.mcp_client import _format_mcp_result

_SERVER_NAME = "microsoft-learn"
_DEFAULT_URL = "https://learn.microsoft.com/api/mcp"


def microsoft_learn_enabled() -> bool:
    """Return True when ``microsoft-learn`` is enabled in the MCP registry."""
    settings = effective_settings()
    registry = load_mcp_registry(settings.mcps_dir)
    spec = registry.get(_SERVER_NAME)
    return bool(spec is not None and spec.enabled)


def microsoft_learn_mcp_connection() -> dict[str, Any] | None:
    """Build MultiServerMCPClient connection for Microsoft Learn, or None."""
    settings = effective_settings()
    registry = load_mcp_registry(settings.mcps_dir)
    spec = registry.get(_SERVER_NAME)
    if spec is None or not spec.enabled:
        return None
    if spec.transport not in {"streamable_http", "sse"}:
        return None
    # Allow empty url in registry → official default.
    if not spec.url:
        spec = replace(spec, transport="streamable_http", url=_DEFAULT_URL)
    return build_http_connection(spec, settings)


async def _call_learn_tool(tool_name: str, arguments: dict[str, Any]) -> str:
    """Invoke one Microsoft Learn MCP tool and flatten the result text."""
    conn = microsoft_learn_mcp_connection()
    if conn is None:
        return (
            "Microsoft Learn MCP is disabled or missing from mcps/registry.json. "
            "Enable server `microsoft-learn` to search official docs."
        )
    client = MultiServerMCPClient(
        {_SERVER_NAME: conn},
        handle_tool_errors=True,
    )
    try:
        async with client.session(_SERVER_NAME) as session:
            result = await session.call_tool(tool_name, arguments=arguments)
    except Exception as exc:  # noqa: BLE001
        return f"MCP error: Microsoft Learn {tool_name} failed: {exc}"
    return _format_mcp_result(result)


@tool
async def microsoft_docs_search(query: str) -> str:
    """Search official Microsoft Learn documentation (how-to, config, limits).

    Use when you need trusted steps for Windows, WinRM, PowerShell, Azure,
    .NET, IIS, Active Directory, or other Microsoft products before running
    host commands. Prefer this over inventing undocumented switches.
    """
    q = (query or "").strip()
    if not q:
        return "MCP error: microsoft_docs_search requires a non-empty query"
    return await _call_learn_tool("microsoft_docs_search", {"query": q})


@tool
async def microsoft_docs_fetch(url: str) -> str:
    """Fetch one Microsoft documentation page as markdown.

    Pass a full ``https://learn.microsoft.com/...`` (or other official Microsoft
    docs) URL from a prior ``microsoft_docs_search`` hit when you need the full
    procedure text.
    """
    target = (url or "").strip()
    if not target:
        return "MCP error: microsoft_docs_fetch requires a url"
    return await _call_learn_tool("microsoft_docs_fetch", {"url": target})


@tool
async def microsoft_code_sample_search(query: str, language: str = "") -> str:
    """Search official Microsoft / Azure code samples and snippets.

    Optional ``language`` filter (e.g. ``powershell``, ``csharp``, ``python``).
    Use when you need a correct command or API example before executing it.
    """
    q = (query or "").strip()
    if not q:
        return "MCP error: microsoft_code_sample_search requires a non-empty query"
    args: dict[str, Any] = {"query": q}
    lang = (language or "").strip()
    if lang:
        args["language"] = lang
    return await _call_learn_tool("microsoft_code_sample_search", args)


def get_microsoft_learn_tools() -> list:
    """Return curated Learn tools when the registry server is enabled."""
    if not microsoft_learn_enabled():
        return []
    return [
        microsoft_docs_search,
        microsoft_docs_fetch,
        microsoft_code_sample_search,
    ]

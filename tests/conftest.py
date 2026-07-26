"""Pytest defaults for unit/integration markers and LLM network guard.

Unmarked tests under ``tests/`` receive ``unit`` unless they live under
``tests/integration/`` (auto-marked ``integration``). Unregistered markers are
rejected via ``--strict-markers`` in ``pyproject.toml``.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-mark tests by path / explicit markers (never both unless justified)."""
    for item in items:
        markers = {m.name for m in item.iter_markers()}
        path = str(item.fspath).replace("\\", "/")
        under_integration = "/tests/integration/" in path
        if under_integration:
            if "unit" in markers and "integration" not in markers:
                raise pytest.UsageError(
                    f"{item.nodeid}: integration-path test must not be marked only unit"
                )
            if "integration" not in markers:
                item.add_marker(pytest.mark.integration)
            continue
        if "integration" in markers or "unit" in markers:
            continue
        item.add_marker(pytest.mark.unit)


def _host_port(url: str) -> tuple[str, int | None]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host, parsed.port


def _looks_like_llm_endpoint(url: str) -> bool:
    text = (url or "").lower()
    host, port = _host_port(text if "://" in text else f"https://{text}")
    if any(
        needle in text
        for needle in (
            "openai.com",
            "api.anthropic",
            "googleapis.com",
            "openrouter.ai",
            "litellm",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",
        )
    ):
        return True
    if port in {4000, 4001}:
        return True
    if host in {"localhost", "127.0.0.1", "0.0.0.0"} and port in {4000, 4001}:
        return True
    return False


@pytest.fixture(autouse=True)
def _block_external_llm_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if mandatory tests attempt a real LLM HTTP call.

    Opt in to real providers with ``AUDITOR_ALLOW_EXTERNAL_LLM=1`` (optional
    external-provider suite only — never required for PR CI).
    """
    if os.environ.get("AUDITOR_ALLOW_EXTERNAL_LLM", "").strip() in {"1", "true", "yes"}:
        return

    def _guard(method: str, url: Any, *args: Any, **kwargs: Any) -> None:
        target = str(url)
        if _looks_like_llm_endpoint(target):
            raise RuntimeError(
                f"External LLM HTTP call blocked in mandatory tests: {method} {target}. "
                "Use DeterministicFakeChatModel / use_chat_model_factory, or set "
                "AUDITOR_ALLOW_EXTERNAL_LLM=1 for the optional provider suite."
            )

    real_client_request = httpx.Client.request
    real_async_request = httpx.AsyncClient.request

    def client_request(self: httpx.Client, method: str, url: Any, *args: Any, **kwargs: Any):
        _guard(method, url)
        return real_client_request(self, method, url, *args, **kwargs)

    async def async_client_request(
        self: httpx.AsyncClient, method: str, url: Any, *args: Any, **kwargs: Any
    ):
        _guard(method, url)
        return await real_async_request(self, method, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "request", client_request)
    monkeypatch.setattr(httpx.AsyncClient, "request", async_client_request)

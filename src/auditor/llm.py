"""LiteLLM-backed chat model factory.

Constructs the LangChain chat model used by assess, finalize, and ad-hoc nodes.
The auditor never calls a vendor API directly; all LLM traffic goes through the
LiteLLM OpenAI-compatible proxy configured by ``Settings.litellm_*``.

We use ``langchain_openai.ChatOpenAI`` pointed at LiteLLM's ``/v1`` base URL so
tool-calling (required by the assess loop) behaves consistently across providers
that LiteLLM fronts. Invoked at graph startup and per ad-hoc command handler.

Tests may install a deterministic factory via
:func:`auditor.testing.fake_llm.use_chat_model_factory` without branching on CI.
"""

from __future__ import annotations

import httpx
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from auditor.config import Settings, get_settings


def build_chat_model(settings: Settings | None = None) -> BaseChatModel:
    """Construct a streaming chat model routed through LiteLLM.

    Normalizes ``litellm_base_url`` so callers may pass either
    ``http://host:4000`` or ``http://host:4000/v1``. Streaming is enabled so
    Open WebUI SSE progress / token delivery works when wired through the API
    layer (graph nodes themselves mostly use ``ainvoke``).

    When ``litellm_ssl_verify`` is ``False``, TLS certificate verification is
    disabled (needed for InfraAx LAN HTTPS with a self-signed cert on IP).

    Args:
        settings: Optional settings override; defaults to ``get_settings()``.

    Returns:
        A ``BaseChatModel`` instance ready for ``ainvoke`` / ``bind_tools``.
    """
    settings = settings or get_settings()
    # Late import keeps production import graph free of test-only cycles.
    from auditor.testing.fake_llm import active_chat_model_factory

    factory = active_chat_model_factory()
    if factory is not None:
        return factory(settings)

    base = settings.litellm_base_url.rstrip("/")
    # ChatOpenAI expects the OpenAI API root that already includes /v1.
    if not base.endswith("/v1"):
        base = f"{base}/v1"

    kwargs: dict = {
        "model": settings.litellm_model,
        "api_key": settings.litellm_api_key,
        "base_url": base,
        "temperature": 0,  # deterministic audit judgments
        "streaming": True,
    }
    if not settings.litellm_ssl_verify:
        kwargs["http_client"] = httpx.Client(verify=False, timeout=120.0)
        kwargs["http_async_client"] = httpx.AsyncClient(verify=False, timeout=120.0)

    return ChatOpenAI(**kwargs)

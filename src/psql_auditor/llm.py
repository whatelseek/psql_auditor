"""LiteLLM-backed chat model factory.

The auditor never calls a vendor API directly. All LLM traffic goes through the
LiteLLM OpenAI-compatible proxy configured by ``Settings.litellm_*``.

We use ``langchain_openai.ChatOpenAI`` pointed at LiteLLM's ``/v1`` base URL so
tool-calling (required by the assess loop) behaves consistently across providers
that LiteLLM fronts.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from psql_auditor.config import Settings, get_settings


def build_chat_model(settings: Settings | None = None) -> BaseChatModel:
    """Construct a streaming chat model routed through LiteLLM.

    Normalizes ``litellm_base_url`` so callers may pass either
    ``http://host:4000`` or ``http://host:4000/v1``. Streaming is enabled so
    Open WebUI SSE progress / token delivery works when wired through the API
    layer (graph nodes themselves mostly use ``ainvoke``).

    Args:
        settings: Optional settings override; defaults to ``get_settings()``.

    Returns:
        A ``BaseChatModel`` instance (``ChatOpenAI``) ready for ``ainvoke`` /
        ``bind_tools``.
    """
    settings = settings or get_settings()
    base = settings.litellm_base_url.rstrip("/")
    # ChatOpenAI expects the OpenAI API root that already includes /v1.
    if not base.endswith("/v1"):
        base = f"{base}/v1"

    return ChatOpenAI(
        model=settings.litellm_model,
        api_key=settings.litellm_api_key,
        base_url=base,
        temperature=0,  # deterministic audit judgments
        streaming=True,
    )

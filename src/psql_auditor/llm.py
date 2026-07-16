"""LiteLLM-backed chat model factory."""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from psql_auditor.config import Settings, get_settings


def build_chat_model(settings: Settings | None = None) -> BaseChatModel:
    """Return a streaming chat model routed through the LiteLLM OpenAI-compatible proxy.

    Uses ChatOpenAI pointed at LiteLLM so tool-calling works consistently.
    """
    settings = settings or get_settings()
    base = settings.litellm_base_url.rstrip("/")
    # ChatOpenAI expects the API root; LiteLLM serves /v1/chat/completions
    if not base.endswith("/v1"):
        base = f"{base}/v1"

    return ChatOpenAI(
        model=settings.litellm_model,
        api_key=settings.litellm_api_key,
        base_url=base,
        temperature=0,
        streaming=True,
    )

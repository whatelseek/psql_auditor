"""Test helpers and injectable fakes (not used by production runtime paths)."""

from auditor.testing.fake_llm import DeterministicFakeChatModel, use_chat_model_factory

__all__ = ["DeterministicFakeChatModel", "use_chat_model_factory"]

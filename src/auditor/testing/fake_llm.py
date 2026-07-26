"""Deterministic, network-free chat model for mandatory tests.

Inject via :func:`use_chat_model_factory` so production code keeps using
:func:`auditor.llm.build_chat_model` without ``if CI`` branches.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any
from uuid import uuid4

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import ConfigDict, PrivateAttr

from auditor.config import Settings

ChatModelFactory = Callable[[Settings], BaseChatModel]

_FACTORY: ChatModelFactory | None = None


def use_chat_model_factory(factory: ChatModelFactory | None) -> ChatModelFactory | None:
    """Install or clear a process-wide override for :func:`auditor.llm.build_chat_model`.

    Returns the previous factory (for nested test fixtures).
    """
    global _FACTORY
    previous = _FACTORY
    _FACTORY = factory
    return previous


def active_chat_model_factory() -> ChatModelFactory | None:
    """Return the currently installed chat-model factory override, if any."""
    return _FACTORY


class DeterministicFakeChatModel(BaseChatModel):
    """Fixed-output chat model that records calls and never opens a network socket.

    Supports structured JSON-ish replies, malformed output, timeouts, and
    provider failures so workflow tests can exercise error paths without an LLM.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    _response_queue: list[str] = PrivateAttr(default_factory=list)
    _default_response: str = PrivateAttr(default='{"ok": true}')
    _fail_with: BaseException | None = PrivateAttr(default=None)
    _timeout: bool = PrivateAttr(default=False)
    _calls: list[dict[str, Any]] = PrivateAttr(default_factory=list)
    _bound_tools: list[Any] = PrivateAttr(default_factory=list)

    def __init__(
        self,
        *,
        responses: Sequence[str] | None = None,
        default_response: str = '{"ok": true}',
        fail_with: BaseException | None = None,
        timeout: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._response_queue = list(responses or [])
        self._default_response = default_response
        self._fail_with = fail_with
        self._timeout = timeout

    @property
    def _llm_type(self) -> str:
        return "deterministic-fake"

    @property
    def calls(self) -> list[dict[str, Any]]:
        """Recorded invoke payloads for prompt/parameter assertions."""
        return self._calls

    @property
    def bound_tools(self) -> list[Any]:
        """Tool schemas passed to the last ``bind_tools`` call."""
        return self._bound_tools

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> DeterministicFakeChatModel:
        """Record tool schemas; return self (tools are not executed)."""
        self._bound_tools = list(tools)
        return self

    def _next_content(self) -> str:
        if self._response_queue:
            return self._response_queue.pop(0)
        return self._default_response

    def _record(self, messages: Sequence[BaseMessage], **kwargs: Any) -> None:
        self._calls.append(
            {
                "messages": list(messages),
                "kwargs": dict(kwargs),
            }
        )

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        self._record(messages, stop=stop, **kwargs)
        if self._timeout:
            raise TimeoutError("DeterministicFakeChatModel simulated timeout")
        if self._fail_with is not None:
            raise self._fail_with
        message = AIMessage(content=self._next_content(), id=str(uuid4()))
        return ChatResult(generations=[ChatGeneration(message=message)])

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        return self._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

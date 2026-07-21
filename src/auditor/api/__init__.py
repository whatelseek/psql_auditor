"""HTTP API package for the LangGraph auditor.

Exposes the audit agent behind an OpenAI-compatible surface so Open WebUI
(and any OpenAI SDK client) can chat with the agent without a custom protocol.

Pipeline role:
    This package is the **operator-facing entry point** for interactive audits.
    Requests arrive as chat completions, are routed through intent classification,
    and invoke ``auditor.graph.AuditorGraph`` to run or resume LangGraph workflows.

Key modules:
    * ``app`` — FastAPI application factory, ``/healthz`` liveness probe, and the
      ``auditor`` console-script entrypoint (``uvicorn``).
    * ``openai_compat`` — ``/v1/models``, ``/v1/chat/completions``, and
      ``/v1/responses`` (+ SSE streaming for progress).
    * ``stream_progress`` — Maps internal ``ProgressEvent`` objects to OpenAI
      chat-completion chunks or Responses API SSE events.
"""

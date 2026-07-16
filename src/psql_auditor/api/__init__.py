"""HTTP API package.

Exposes the LangGraph auditor behind an OpenAI-compatible surface so Open WebUI
(and any OpenAI SDK client) can chat with the agent without a custom protocol.

* ``app`` — FastAPI application factory and uvicorn entrypoint
* ``openai_compat`` — ``/v1/models`` and ``/v1/chat/completions`` (+ SSE)
"""

"""LangGraph IT infrastructure auditor package.

Checklist-driven security auditor for frameworks you drop into ``agents/``
(PostgreSQL, Ubuntu, Windows, …):

* ``checklist`` — parse Markdown requirements into structured objects
* ``graph`` — LangGraph workflow that assesses each requirement in order
* ``tools`` — SSH + LangChain MCP adapters (Postgres) helpers
* ``llm`` — LiteLLM-backed chat model factory
* ``api`` — OpenAI-compatible HTTP API for Open WebUI

Typical entrypoints:

* HTTP: ``auditor.api.app:app`` (uvicorn / Docker)
* CLI: ``auditor`` console script → ``api.app:main``
"""

__version__ = "0.1.0"

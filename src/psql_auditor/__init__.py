"""PostgreSQL LangGraph auditor package.

This package implements a checklist-driven security auditor for PostgreSQL:

* ``checklist`` — parse Markdown requirements into structured objects
* ``graph`` — LangGraph workflow that assesses each requirement in order
* ``tools`` — SSH, SQL, and MCP helpers used during assessment
* ``llm`` — LiteLLM-backed chat model factory
* ``api`` — OpenAI-compatible HTTP API for Open WebUI

Typical entrypoints:

* HTTP: ``psql_auditor.api.app:app`` (uvicorn / Docker)
* CLI: ``psql-auditor`` console script → ``api.app:main``
"""

__version__ = "0.1.0"

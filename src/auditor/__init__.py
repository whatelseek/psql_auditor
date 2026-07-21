"""LangGraph IT infrastructure auditor package (``psql_auditor``).

Checklist-driven security auditor for frameworks you drop into ``agents/``
(PostgreSQL, Ubuntu, Windows, IT audit, …). The operator describes what to
audit in natural language; the graph routes to the right checklist, gathers
evidence via SSH and MCP tools, and produces a fixed-format report.

Pipeline role:
    Top-level package that wires configuration, LLM calls, tool adapters,
    procedural memory, and the LangGraph audit workflow into deployable
    HTTP and CLI entrypoints.

Key subpackages:
    * ``checklist`` — Parse Markdown requirements into structured objects.
    * ``graph`` — LangGraph workflow: route → assess → reconnect / HITL → finalize.
    * ``tools`` — SSH host inspection and LangChain MCP adapters (Postgres, NetBox).
    * ``memory`` — Long-term procedural playbooks (preferred tool recipes per REQ).
    * ``llm`` — LiteLLM-backed chat model factory.
    * ``api`` — OpenAI-compatible HTTP API for Open WebUI.

Typical entrypoints:
    * HTTP: ``auditor.api.app:app`` (uvicorn / Docker Compose).
    * CLI: ``auditor`` console script → ``api.app:main``.
"""

__version__ = "0.1.0"

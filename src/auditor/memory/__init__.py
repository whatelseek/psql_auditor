"""Memory package: long-term procedural playbooks.

Pipeline role:
    Supplies ``PlaybookMemory``, which the audit graph consults before each
    requirement assessment and updates after successful tool calls. Seed YAML
    under ``agents/playbooks/`` is merged with learned recipes from the results
    warehouse Postgres (``playbook_memory``) or JSON fallback.

Key entry point:
    ``PlaybookMemory`` — LangGraph ``InMemoryStore`` cache + Postgres/JSON persist.
"""

from auditor.memory.playbook_store import PlaybookMemory

__all__ = ["PlaybookMemory"]

"""Memory package: long-term procedural playbooks.

Pipeline role:
    Supplies ``PlaybookMemory``, which the audit graph consults before each
    requirement assessment and updates after successful tool calls. Seed YAML
    under ``agents/playbooks/`` is merged with learned recipes on disk.

Key entry point:
    ``PlaybookMemory`` — LangGraph ``InMemoryStore`` + ``MEMORY_DIR`` persistence.
"""

from auditor.memory.playbook_store import PlaybookMemory

__all__ = ["PlaybookMemory"]

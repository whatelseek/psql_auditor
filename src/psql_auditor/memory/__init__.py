"""Long-term procedural memory (framework playbooks).

Uses LangGraph-style store semantics: namespace ``(\"playbooks\", framework_id)``
with keys per ``REQ-*``. Seed data lives under ``agents/playbooks/``; learned
updates persist under ``MEMORY_DIR``.
"""

from psql_auditor.memory.playbook_store import PlaybookMemory, get_playbook_memory

__all__ = ["PlaybookMemory", "get_playbook_memory"]

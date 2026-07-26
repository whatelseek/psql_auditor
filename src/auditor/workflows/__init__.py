"""LangGraph workflow nodes, builders, and runners for the auditor.

Ownership:
    * ``helpers`` — pure transforms and routing predicates
    * ``dependencies`` — injectable runtime container and registries
    * ``builder`` — StateGraph topology and compilation
    * ``intake`` / ``discovery`` / ``assessment`` / ``hitl`` / ``finalize`` — nodes
    * ``tool_execution`` — tool-call loop used by assessment
    * ``runner`` / ``multi_runner`` — lifecycle and multi-host scheduling

Dependency direction: ``graph.py`` → workflows → domain services.
Workflow modules must **not** import ``auditor.graph``.
"""

from __future__ import annotations

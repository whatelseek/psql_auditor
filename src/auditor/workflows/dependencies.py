"""Injectable runtime dependencies and process-scoped registries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from auditor.config import Settings
from auditor.evidence_store import EvidenceStore


@dataclass(slots=True)
class EvidenceRegistry:
    """Run-id → :class:`EvidenceStore` map shared by concurrent framework jobs."""

    stores: dict[str, EvidenceStore] = field(default_factory=dict)

    def get(self, run_id: str) -> EvidenceStore | None:
        return self.stores.get(run_id)

    def __setitem__(self, run_id: str, store: EvidenceStore) -> None:
        self.stores[run_id] = store

    def pop(self, run_id: str, default: EvidenceStore | None = None) -> EvidenceStore | None:
        return self.stores.pop(run_id, default)


@dataclass(slots=True)
class MultiSessionRegistry:
    """In-memory multi-framework session bookkeeping (also persisted to disk)."""

    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get(self, thread_id: str) -> dict[str, Any] | None:
        return self.sessions.get(thread_id)

    def __setitem__(self, thread_id: str, session: dict[str, Any]) -> None:
        self.sessions[thread_id] = session

    def pop(self, thread_id: str, default: dict[str, Any] | None = None) -> dict[str, Any] | None:
        return self.sessions.pop(thread_id, default)

    def values(self):
        return self.sessions.values()

    def items(self):
        return self.sessions.items()

    def __contains__(self, thread_id: object) -> bool:
        return thread_id in self.sessions


@dataclass(slots=True)
class GraphDependencies:
    """Explicit runtime dependencies for workflow nodes and runners.

    Constructed by :class:`~auditor.graph.AuditorGraph`. Workflow modules receive
    this container (or the façade that exposes the same fields) instead of
    reaching into unrelated orchestration state.
    """

    settings: Settings
    tools: list[Any]
    tools_by_name: dict[str, Any]
    evidence_model: Any
    evidence_model_ssh: Any
    fill_model: Any
    playbooks: Any | None
    evidence: EvidenceRegistry
    multi_sessions: MultiSessionRegistry
    mcp_pool: Any = None
    results_store: Any | None = None
    task_registry: Any = None
    orphan_tasks: dict[str, Any] = field(default_factory=dict)  # deprecated

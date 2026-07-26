"""LangGraph StateGraph construction and compilation."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from auditor.state import AuditorState
from auditor.workflows.protocols import AuditRuntime


def build_main_graph(runtime: AuditRuntime, checkpointer: Any | None = None):
    """Compile the main audit StateGraph with reconnect and HITL cycles.

    Args:
        checkpointer: Optional saver for CORE-005 run-scoped graphs. Defaults to
            ``runtime._checkpointer`` (process-local / legacy).

    Returns:
        Compiled graph: route → load → host facts → assess → finalize.
    """
    graph = StateGraph(AuditorState)
    graph.add_node("route_framework", runtime.route_framework_node)
    graph.add_node("load_framework", runtime.load_framework)
    graph.add_node("collect_host_facts", runtime.collect_host_facts)
    graph.add_node("assess_parallel", runtime.assess_parallel)
    graph.add_node("reconnect_session", runtime.reconnect_session)
    graph.add_node("human_gate", runtime.human_gate)
    graph.add_node("finalize", runtime.finalize)

    graph.add_edge(START, "route_framework")
    graph.add_edge("route_framework", "load_framework")
    graph.add_edge("load_framework", "collect_host_facts")
    graph.add_edge("collect_host_facts", "assess_parallel")
    graph.add_conditional_edges(
        "assess_parallel",
        runtime.route_after_assess,
        {
            "reconnect_session": "reconnect_session",
            "human_gate": "human_gate",
            "finalize": "finalize",
        },
    )
    # Cycle: after reconnect, re-run assess on remaining pending_ids only.
    graph.add_edge("reconnect_session", "assess_parallel")
    graph.add_conditional_edges(
        "human_gate",
        runtime.route_after_hitl,
        {
            "assess_parallel": "assess_parallel",
            "human_gate": "human_gate",
            "finalize": "finalize",
        },
    )
    graph.add_edge("finalize", END)
    saver = checkpointer if checkpointer is not None else runtime._checkpointer
    return graph.compile(checkpointer=saver)


def build_intake_graph(runtime: AuditRuntime, checkpointer: Any | None = None):
    """Compile the pre-audit intake questionnaire subgraph.

    Args:
        checkpointer: Optional saver for CORE-005 run-scoped graphs.

    Returns:
        Single-node graph ending at ``intake_gate`` (may interrupt).
    """
    graph = StateGraph(AuditorState)
    graph.add_node("intake_gate", runtime.intake_gate)
    graph.add_edge(START, "intake_gate")
    graph.add_edge("intake_gate", END)
    saver = checkpointer if checkpointer is not None else runtime._checkpointer
    return graph.compile(checkpointer=saver)

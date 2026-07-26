"""Characterization: LangGraph node names and router contracts."""

from __future__ import annotations

from pathlib import Path

from auditor.config import Settings
from auditor.graph import AuditorGraph
from auditor.state import Finding


def _graph() -> AuditorGraph:
    return AuditorGraph(settings=Settings(_env_file=None, agents_dir=Path("agents")))


def test_main_graph_node_names_frozen():
    g = _graph()
    nodes = set(g.graph.get_graph().nodes) - {"__start__", "__end__"}
    assert nodes == {
        "route_framework",
        "load_framework",
        "collect_host_facts",
        "assess_parallel",
        "reconnect_session",
        "human_gate",
        "finalize",
    }


def test_intake_graph_node_names_frozen():
    g = _graph()
    nodes = set(g.intake_graph.get_graph().nodes) - {"__start__", "__end__"}
    assert nodes == {"intake_gate"}


def test_route_after_assess_contract():
    g = _graph()
    assert (
        g.route_after_assess({"pending_ids": ["REQ-001"], "retry_count": 0}) == "reconnect_session"
    )
    assert (
        g.route_after_assess({"pending_ids": ["REQ-001"], "retry_count": 99, "findings": {}})
        == "finalize"
    )


def test_route_after_hitl_contract():
    g = _graph()
    assert g.route_after_hitl({"pending_ids": ["REQ-001"]}) == "assess_parallel"
    assert g.route_after_hitl({"pending_ids": [], "findings": {}}) == "finalize"


def test_public_helpers_reexported():
    from auditor.graph import _hitl_candidates, _is_recoverable_finding
    from auditor.workflows.helpers import (
        _hitl_candidates as hc,
    )
    from auditor.workflows.helpers import (
        _is_recoverable_finding as ir,
    )

    f = Finding(
        requirement_id="REQ-001",
        status="error",
        evidence="SSH error: TimeoutError",
    )
    assert _is_recoverable_finding is ir
    assert _is_recoverable_finding(f)
    assert _hitl_candidates is hc

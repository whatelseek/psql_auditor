from pathlib import Path

from auditor.config import Settings
from auditor.graph import AuditorGraph
from auditor.state import Finding


def test_route_after_assess_cycles_when_retries_remain():
    settings = Settings(
        _env_file=None,
        agents_dir=Path("agents"),
        max_session_retries=2,
    )
    graph = AuditorGraph(settings=settings)
    assert (
        graph.route_after_assess(
            {"pending_ids": ["REQ-001"], "retry_count": 0}
        )
        == "reconnect_session"
    )
    assert (
        graph.route_after_assess(
            {"pending_ids": ["REQ-001"], "retry_count": 2, "findings": {}}
        )
        == "finalize"
    )
    assert (
        graph.route_after_assess({"pending_ids": [], "retry_count": 0, "findings": {}})
        == "finalize"
    )


def test_assess_queues_recoverable_failures():
    # Smoke: recoverable marker stays in pending for the cycle.
    f = Finding(
        requirement_id="REQ-009",
        status="error",
        evidence="SSH error: TimeoutError: timed out",
    )
    from auditor.graph import _is_recoverable_finding

    assert _is_recoverable_finding(f)

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from psql_auditor.checklist import Requirement
from psql_auditor.config import Settings
from psql_auditor.graph import AuditorGraph, _is_recoverable_finding
from psql_auditor.state import Finding


@pytest.mark.asyncio
async def test_assess_parallel_runs_workers_and_merges_findings():
    settings = Settings(
        _env_file=None,
        max_parallel_assessments=3,
        max_tool_rounds_per_item=1,
        agents_dir=Path("agents"),
    )
    graph = AuditorGraph(settings=settings)

    async def fake_assess(req_id, requirement, user_request, framework_id="", store=None):
        await asyncio.sleep(0)  # yield to event loop
        return Finding(
            requirement_id=req_id,
            title=requirement.title,
            status="pass",
            evidence="ok",
        )

    reqs = {
        "REQ-001": Requirement(id="REQ-001", title="A"),
        "REQ-002": Requirement(id="REQ-002", title="B"),
        "REQ-003": Requirement(id="REQ-003", title="C"),
    }
    with patch.object(graph, "_fill_requirement_cells", side_effect=fake_assess):
        result = await graph.assess_parallel(
            {
                "requirements": reqs,
                "pending_ids": list(reqs.keys()),
                "user_request": "audit",
            }
        )

    assert set(result["findings"]) == {"REQ-001", "REQ-002", "REQ-003"}
    assert result["pending_ids"] == []
    assert all(f.status == "pass" for f in result["findings"].values())


@pytest.mark.asyncio
async def test_assess_parallel_respects_concurrency_limit():
    settings = Settings(
        _env_file=None,
        max_parallel_assessments=2,
        agents_dir=Path("agents"),
    )
    graph = AuditorGraph(settings=settings)

    current = 0
    peak = 0
    lock = asyncio.Lock()

    async def fake_assess(req_id, requirement, user_request, framework_id="", store=None):
        nonlocal current, peak
        async with lock:
            current += 1
            peak = max(peak, current)
        await asyncio.sleep(0.05)
        async with lock:
            current -= 1
        return Finding(
            requirement_id=req_id,
            title=requirement.title,
            status="pass",
            evidence="ok",
        )

    reqs = {
        f"REQ-{i:03d}": Requirement(id=f"REQ-{i:03d}", title=str(i))
        for i in range(1, 6)
    }
    with patch.object(graph, "_fill_requirement_cells", side_effect=fake_assess):
        await graph.assess_parallel(
            {
                "requirements": reqs,
                "pending_ids": list(reqs.keys()),
                "user_request": "audit",
            }
        )

    assert peak <= 2
    assert peak >= 1


def test_recoverable_finding_detects_mcp_errors():
    f = Finding(
        requirement_id="REQ-001",
        status="error",
        evidence="MCP error: ConnectionError: session closed",
    )
    assert _is_recoverable_finding(f)
    f2 = Finding(
        requirement_id="REQ-002",
        status="fail",
        evidence="ssl=off",
    )
    assert not _is_recoverable_finding(f2)

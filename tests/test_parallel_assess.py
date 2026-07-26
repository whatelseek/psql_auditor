import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.fixtures.canonical_audit import (
    ASSET_LINUX_01_ID,
    CLIENT_ALPHA_ID,
    FRAMEWORK_LINUX_ID,
    FRAMEWORK_VERSION,
    RUN_ALPHA_CURRENT_ID,
)

from auditor.checklist import Requirement
from auditor.config import Settings
from auditor.domain.assessment_result import AssessmentResult
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph, _is_recoverable_finding
from auditor.state import Finding


@pytest.mark.asyncio
async def test_assess_parallel_runs_workers_and_merges_findings():
    settings = Settings(
        _env_file=None,
        max_parallel_assessments=3,
        max_tool_rounds_per_item=1,
        agents_dir=Path("agents"),
    )
    graph = AuditorGraph(settings=settings)

    async def fake_assess(
        req_id, requirement, user_request, framework_id="", store=None, **_kwargs
    ):
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

    assert len(result["findings"]) == 3
    assert {f.requirement_id for f in result["findings"].values()} == {
        "REQ-001",
        "REQ-002",
        "REQ-003",
    }
    assert all(f.result_id for f in result["findings"].values())
    assert set(result["findings"]) == {f.result_id for f in result["findings"].values()}
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

    async def fake_assess(
        req_id, requirement, user_request, framework_id="", store=None, **_kwargs
    ):
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

    reqs = {f"REQ-{i:03d}": Requirement(id=f"REQ-{i:03d}", title=str(i)) for i in range(1, 6)}
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


@pytest.mark.asyncio
async def test_assess_parallel_exception_produces_structured_error(tmp_path: Path):
    """CORE-004: exception path builds AssessmentResult with AssessmentError."""
    settings = Settings(
        _env_file=None,
        max_parallel_assessments=1,
        max_tool_rounds_per_item=1,
        agents_dir=Path("agents"),
        evidence_dir=tmp_path,
    )
    graph = AuditorGraph(settings=settings)
    store = EvidenceStore(
        tmp_path / "client_alpha" / RUN_ALPHA_CURRENT_ID, run_id=RUN_ALPHA_CURRENT_ID
    )
    store.write_run_meta(
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_version=FRAMEWORK_VERSION,
    )

    async def boom(req_id, requirement, user_request, framework_id="", store=None, **_kwargs):
        raise ConnectionError("ssh session closed")

    reqs = {"REQ-001": Requirement(id="REQ-001", title="A", severity="High", category="auth")}
    with patch.object(graph, "_fill_requirement_cells", side_effect=boom):
        result = await graph.assess_parallel(
            {
                "requirements": reqs,
                "pending_ids": ["REQ-001"],
                "user_request": "audit",
                "framework_id": FRAMEWORK_LINUX_ID,
                "framework_version": FRAMEWORK_VERSION,
                "client_id": CLIENT_ALPHA_ID,
                "audit_run_id": RUN_ALPHA_CURRENT_ID,
                "asset_id": ASSET_LINUX_01_ID,
                "evidence_run_id": RUN_ALPHA_CURRENT_ID,
                "evidence_run_dir": str(store.root),
            }
        )

    findings = result["findings"]
    assert len(findings) == 1
    finding = next(iter(findings.values()))
    assert isinstance(finding, AssessmentResult)
    assert not isinstance(finding, Finding)
    assert finding.status == "error"
    assert finding.error is not None
    assert finding.error.error_type == "ConnectionError"
    assert "ssh session closed" in finding.error.message
    assert finding.observation == ""
    assert "ConnectionError" not in finding.observation
    assert finding.client_id == CLIENT_ALPHA_ID
    assert finding.audit_run_id == RUN_ALPHA_CURRENT_ID
    assert finding.asset_id == ASSET_LINUX_01_ID
    assert finding.framework_id == FRAMEWORK_LINUX_ID
    assert finding.framework_version == FRAMEWORK_VERSION
    assert finding.requirement_id == "REQ-001"
    assert finding.result_id

    raw = store.load_finding(FRAMEWORK_LINUX_ID, "REQ-001")
    assert raw is not None
    assert raw.get("status") == "error"
    assert isinstance(raw.get("error"), dict)
    assert raw["error"]["error_type"] == "ConnectionError"
    assert raw.get("observation") == ""
    assert "Cell fill failed" not in json.dumps(raw)
    loaded = AssessmentResult.from_persist_dict(raw)
    assert loaded.identity.result_id == finding.result_id
    assert loaded.identity.as_flat_dict() == finding.identity.as_flat_dict()
    assert loaded.error is not None
    assert loaded.error.error_type == "ConnectionError"


def test_production_error_paths_do_not_embed_exceptions_in_observation():
    """Static guard: assessment/discovery exception handlers stay structured."""
    root = Path(__file__).resolve().parents[1]
    targets = [
        root / "src/auditor/workflows/assessment.py",
        root / "src/auditor/workflows/discovery.py",
    ]
    forbidden = (
        'evidence=f"Cell fill failed:',
        'evidence=f"{type(exc)',
        "evidence=f'{type(exc)",
    )
    for path in targets:
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{path.name} still embeds exceptions via {needle!r}"
        assert "from_execution_error" in text

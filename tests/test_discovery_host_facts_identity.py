"""Regression: host_facts discovery must bind audit_run_id before write_finding."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.fixtures.canonical_audit import (
    ASSET_LINUX_01_ID,
    CLIENT_ALPHA_ID,
    FRAMEWORK_VERSION,
    RUN_ALPHA_CURRENT_ID,
)

from auditor.checklist import Requirement
from auditor.config import Settings
from auditor.domain.assessment_result import AssessmentResult, ResultIdentity
from auditor.domain.result_identity import new_result_id
from auditor.evidence_store import EvidenceStore
from auditor.graph import AuditorGraph
from auditor.host_facts import HostFacts
from auditor.workflows.discovery import _discovery_identity_state


def test_discovery_identity_state_merges_store_meta(tmp_path: Path):
    store = EvidenceStore(tmp_path / "run", run_id="run")
    store.write_run_meta(
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_version=FRAMEWORK_VERSION,
    )
    merged = _discovery_identity_state(store, {"client_id": CLIENT_ALPHA_ID})
    assert merged["audit_run_id"] == RUN_ALPHA_CURRENT_ID
    assert merged["asset_id"] == ASSET_LINUX_01_ID
    assert merged["framework_version"] == FRAMEWORK_VERSION


@pytest.mark.asyncio
async def test_collect_host_facts_llm_passes_identity_state_to_fill(tmp_path: Path):
    """Without state=..., write_finding raised MissingAuditRunIdError and emptied findings."""
    settings = Settings(
        _env_file=None,
        max_parallel_assessments=2,
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

    seen: list[dict] = []

    async def fake_fill(
        req_id,
        requirement,
        user_request,
        framework_id="",
        store=None,
        state=None,
        **_kwargs,
    ):
        seen.append(dict(state or {}))
        identity = ResultIdentity(
            result_id=new_result_id(),
            client_id=str((state or {}).get("client_id") or ""),
            audit_run_id=str((state or {}).get("audit_run_id") or ""),
            asset_id=str((state or {}).get("asset_id") or ""),
            framework_id="host_facts",
            framework_version=str((state or {}).get("framework_version") or "1"),
            requirement_id=req_id,
        )
        result = AssessmentResult(
            identity=identity,
            status="pass",
            observation=f"{requirement.title}: ok",
            recommendation="",
            title=requirement.title,
            severity=requirement.severity,
            category=requirement.category,
            pass_criteria=requirement.pass_criteria,
        )
        if store is not None:
            store.write_finding(framework_id, req_id, result.to_persist_dict())
        return result

    class _Fw:
        id = "host_facts"
        version = "1"
        path = Path("agents/host_facts.md")

    class _Checklist:
        def by_id(self):
            return {
                "REQ-001": Requirement(
                    id="REQ-001",
                    title="Inventory completeness",
                    severity="High",
                    category="Inventory",
                    pass_criteria="ok",
                )
            }

        def ids(self):
            return ["REQ-001"]

    async def fake_facts_from_evidence(**_kwargs):
        return HostFacts(ssh_host="10.0.0.1", hostname="box", os_id="ubuntu")

    with (
        patch(
            "auditor.workflows.discovery.get_framework",
            return_value=_Fw(),
        ),
        patch(
            "auditor.workflows.discovery.load_framework_checklist",
            return_value=_Checklist(),
        ),
        patch.object(graph, "_fill_requirement_cells", side_effect=fake_fill),
        patch.object(
            graph, "_facts_from_host_facts_evidence", side_effect=fake_facts_from_evidence
        ),
    ):
        facts = await graph._collect_host_facts_llm(
            store=store,
            host_id="10.0.0.1",
            user_request="discover",
            # Intentionally omit state — meta on the store must still bind identity.
        )

    assert facts.hostname == "box"
    assert seen, "fill_requirement_cells was not called"
    assert all(s.get("audit_run_id") == RUN_ALPHA_CURRENT_ID for s in seen)
    assert all(s.get("client_id") == CLIENT_ALPHA_ID for s in seen)
    assert all(s.get("asset_id") == ASSET_LINUX_01_ID for s in seen)

    raw = store.load_finding("host_facts", "REQ-001")
    assert raw is not None
    assert raw.get("status") == "pass"
    assert raw.get("audit_run_id") == RUN_ALPHA_CURRENT_ID
    assert raw.get("observation")
    assert (raw.get("error") or {}).get("error_type") != "MissingAuditRunIdError"
    # Ensure the on-disk payload is not the empty error stub from the old bug.
    assert "MissingAuditRunIdError" not in json.dumps(raw)

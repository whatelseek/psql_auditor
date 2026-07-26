"""CORE-004 — structured AssessmentResult contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.fixtures.canonical_audit import (
    CLIENT_ALPHA_ID,
    FRAMEWORK_VERSION,
    RUN_ALPHA_CURRENT_ID,
    RUN_ALPHA_PREVIOUS_ID,
    build_canonical_scenario,
)

from auditor.domain import (
    AssessmentError,
    AssessmentResult,
    EvidenceRef,
    IncompleteResultIdentityError,
    ResultIdentity,
    logical_key_of,
    new_result_id,
)
from auditor.evidence_store import EvidenceStore
from auditor.result_identity_bind import attach_result_identity
from auditor.state import Finding, render_report


def _identity(**overrides: str) -> ResultIdentity:
    scenario = build_canonical_scenario()
    asset = next(a for a in scenario.assets if a.label == "asset_linux_01")
    base = dict(
        result_id=new_result_id(),
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=asset.asset_id,
        framework_id="framework_linux",
        framework_version=FRAMEWORK_VERSION,
        requirement_id="REQ-001",
    )
    base.update(overrides)
    return ResultIdentity(**base)


def test_create_valid_assessment_result():
    result = AssessmentResult(
        identity=_identity(),
        status="pass",
        observation="SSH root login disabled",
        recommendation="Keep PermitRootLogin no",
        evidence_refs=[EvidenceRef(kind="tool", tool_name="ssh_exec", uri="001_ssh.txt")],
    )
    assert result.requirement_id == "REQ-001"
    assert result.evidence_refs[0].tool_name == "ssh_exec"
    assert result.error is None


def test_reject_missing_or_invalid_identity():
    with pytest.raises(ValidationError):
        ResultIdentity(
            result_id="not-a-uuid",
            client_id=CLIENT_ALPHA_ID,
            audit_run_id=RUN_ALPHA_CURRENT_ID,
            asset_id="aaaaaaaa-1111-4111-8111-111111111111",
            framework_id="framework_linux",
            framework_version="1.0.0",
            requirement_id="REQ-001",
        )
    incomplete = AssessmentResult(
        identity=_identity(client_id="", asset_id=""),
        status="fail",
        observation="x",
    )
    with pytest.raises(IncompleteResultIdentityError):
        incomplete.ensure_persistable()


def test_reject_unsupported_status():
    with pytest.raises(ValidationError):
        AssessmentResult(identity=_identity(), status="unknown")  # type: ignore[arg-type]


def test_serialization_round_trip():
    original = AssessmentResult(
        identity=_identity(result_id="a0000001-0001-4001-8001-000000000099"),
        status="partial",
        observation="Unicode: Уникод-αβγ",
        recommendation="Tighten config",
        evidence_refs=[EvidenceRef(kind="file", uri="req/REQ-001/finding.json")],
        notes="n1",
    )
    payload = original.model_dump()
    restored = AssessmentResult.model_validate(payload)
    assert restored == original
    flat = original.to_persist_dict()
    assert flat["observation"] == original.observation
    assert "evidence" not in flat
    assert "remediation" not in flat
    again = AssessmentResult.from_persist_dict(flat)
    assert again.identity == original.identity
    assert again.observation == original.observation


def test_structured_execution_error():
    err = AssessmentError(
        error_type="TimeoutError",
        message="ssh timed out",
        details={"host": "h1"},
    )
    result = AssessmentResult(
        identity=_identity(),
        status="error",
        observation="",
        recommendation="",
        error=err,
    )
    assert result.error is not None
    assert result.error.error_type == "TimeoutError"
    with pytest.raises(ValidationError):
        AssessmentResult(
            identity=_identity(),
            status="pass",
            error=AssessmentError(error_type="X", message="y"),
        )


def test_identity_preserved_after_correction():
    original = AssessmentResult(
        identity=_identity(result_id="a0000001-0001-4001-8001-000000000098"),
        status="fail",
        observation="bad",
        recommendation="fix",
    )
    corrected = original.with_correction(status="pass", observation="fixed", recommendation="ok")
    assert corrected.identity == original.identity
    assert corrected.status == "pass"
    assert corrected.observation == "fixed"
    assert logical_key_of(corrected).as_tuple() == logical_key_of(original).as_tuple()


def test_evidence_ref_round_trip():
    refs = [
        EvidenceRef(kind="tool", tool_name="ssh_exec", uri="001_ssh.txt", label="ssh"),
        EvidenceRef(kind="url", uri="https://example.test/doc", label="doc"),
    ]
    result = AssessmentResult(identity=_identity(), status="fail", evidence_refs=refs)
    restored = AssessmentResult.model_validate(result.model_dump())
    assert restored.evidence_refs == refs


def test_finding_adapter_conversion():
    result = AssessmentResult(
        identity=_identity(),
        status="fail",
        observation="obs",
        recommendation="rec",
        title="Title",
        severity="High",
    )
    finding = result.to_finding()
    assert isinstance(finding, Finding)
    assert finding.evidence == "obs"
    assert finding.remediation == "rec"
    assert finding.result_id == result.result_id
    back = AssessmentResult.from_finding(finding)
    assert back.observation == "obs"
    assert back.recommendation == "rec"
    assert back.identity.result_id == result.result_id
    # Legacy aliases on dict input map one-way
    legacy = AssessmentResult.from_finding(
        {
            **result.identity.as_flat_dict(),
            "status": "pass",
            "evidence": "legacy-obs",
            "remediation": "legacy-rec",
        }
    )
    assert legacy.observation == "legacy-obs"
    assert legacy.recommendation == "legacy-rec"


def test_persistence_round_trip(tmp_path: Path):
    scenario = build_canonical_scenario()
    result = AssessmentResult.from_finding(scenario.result_by_status("fail"))
    store = EvidenceStore(tmp_path, run_id=f"client_alpha/{RUN_ALPHA_CURRENT_ID}")
    store.write_run_meta(client_id=CLIENT_ALPHA_ID, audit_run_id=RUN_ALPHA_CURRENT_ID)
    path = store.write_finding("framework_postgresql", "REQ-001", result.to_persist_dict())
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["observation"]
    assert "evidence" not in raw or raw.get("observation")
    loaded = AssessmentResult.from_persist_dict(raw)
    assert loaded.identity == result.identity
    assert loaded.status == result.status
    assert loaded.observation == result.observation


def test_malformed_llm_output_cannot_bypass_validation():
    ident = _identity()
    bad = AssessmentResult.from_llm_payload(
        {"status": "pass", "observation": "x", "evidence_refs": "not-a-list"},
        identity=ident,
        title="T",
    )
    assert bad.status == "error"
    assert bad.error is not None
    assert bad.error.error_type == "MalformedModelOutput"
    assert bad.identity == ident
    missing = AssessmentResult.from_llm_payload(None, identity=ident)
    assert missing.status == "error"
    assert missing.error is not None


def test_req001_separated_across_assets_frameworks_runs():
    scenario = build_canonical_scenario()
    results = [
        AssessmentResult.from_finding(f) for f in scenario.results if f.requirement_id == "REQ-001"
    ]
    keys = {logical_key_of(r).as_tuple() for r in results}
    assert len(keys) >= 3
    runs = {r.audit_run_id for r in results}
    assert RUN_ALPHA_PREVIOUS_ID in runs or RUN_ALPHA_CURRENT_ID in runs
    frameworks = {r.framework_id for r in results}
    assert "framework_linux" in frameworks and "framework_postgresql" in frameworks


def test_report_generation_compatible_with_assessment_results():
    from auditor.checklist import Requirement

    scenario = build_canonical_scenario()
    sample = AssessmentResult.from_finding(scenario.result_by_status("fail"))
    findings = {sample.result_id: sample.to_finding()}
    requirements = {
        sample.requirement_id: Requirement(
            id=sample.requirement_id,
            title=sample.title or "REQ",
            category=sample.category or "cat",
            severity=sample.severity or "Medium",
            how_to_verify="verify",
            pass_criteria=sample.pass_criteria or "ok",
        )
    }
    report = render_report(
        "CORE-004 report",
        findings,
        requirements,
        language="en",
    )
    assert "Audit Report" in report
    assert sample.status in report


def test_attach_preserves_identity_on_assessment_result():
    scenario = build_canonical_scenario()
    base = AssessmentResult.from_finding(scenario.result_by_status("fail"))
    corrected = base.with_correction(status="pass", observation="validated")
    bound = attach_result_identity(
        corrected.with_correction(status="fail"),  # content change
        state={
            "client_id": base.client_id,
            "audit_run_id": base.audit_run_id,
            "asset_id": base.asset_id,
            "framework_version": base.framework_version,
        },
        framework_id=base.framework_id,
        existing=base,
    )
    assert bound.result_id == base.result_id
    assert bound.client_id == base.client_id
    assert bound.audit_run_id == base.audit_run_id

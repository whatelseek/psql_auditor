"""Bind CORE-003 identity onto AssessmentResult records during assessment."""

from __future__ import annotations

from typing import Any, Mapping

from auditor.domain.assessment_result import AssessmentResult, ResultIdentity
from auditor.domain.result_identity import (
    IncompleteResultIdentityError,
    new_result_id,
    validate_result_identity,
)
from auditor.state import Finding


def identity_from_state(
    state: Mapping[str, Any] | None,
    *,
    framework_id: str = "",
    framework_version: str = "",
    requirement_id: str = "",
) -> dict[str, str]:
    """Collect identity dimensions from graph state / intake.

    ``client_id`` must be the durable registry id — never a client slug/name
    (CORE-001). Callers that only have a display name must resolve via
    :mod:`auditor.client_registry` before binding.
    """
    st = state or {}
    raw_intake = st.get("intake")
    intake: dict[str, Any] = raw_intake if isinstance(raw_intake, dict) else {}
    client_id = str(st.get("client_id") or intake.get("client_id") or "").strip()
    audit_run_id = str(st.get("audit_run_id") or intake.get("audit_run_id") or "").strip()
    intake_state = st.get("intake_state")
    if not audit_run_id and isinstance(intake_state, dict):
        audit_run_id = str(intake_state.get("audit_run_id") or "").strip()
    if not client_id and isinstance(intake_state, dict):
        client_id = str(intake_state.get("client_id") or "").strip()
    asset_id = str(st.get("asset_id") or "").strip()
    fw = (framework_id or str(st.get("framework_id") or "")).strip()
    if "/" in fw:
        fw = fw.split("/", 1)[-1]
    ver = (framework_version or str(st.get("framework_version") or "")).strip()
    return {
        "client_id": client_id,
        "audit_run_id": audit_run_id,
        "asset_id": asset_id,
        "framework_id": fw,
        "framework_version": ver,
        "requirement_id": (requirement_id or "").strip(),
    }


def attach_result_identity(
    finding: Finding | AssessmentResult,
    *,
    state: Mapping[str, Any] | None = None,
    framework_id: str = "",
    framework_version: str = "",
    existing: Finding | AssessmentResult | Mapping[str, Any] | None = None,
    require_complete: bool = False,
) -> AssessmentResult:
    """Ensure ``finding`` carries result_id + logical key fields.

    Reuses ``result_id`` from ``existing`` when the logical key matches so
    assessment → validation → reporting keep the same physical identity.
    Returns :class:`AssessmentResult` (converts legacy Finding when needed).
    """
    reused_id = ""
    if existing is not None:
        if isinstance(existing, AssessmentResult):
            reused_id = existing.result_id
        elif isinstance(existing, Finding):
            reused_id = existing.result_id
        elif isinstance(existing, Mapping):
            reused_id = str(existing.get("result_id") or "")

    if isinstance(finding, AssessmentResult):
        result = finding
    else:
        # Preserve empty result_id so we can reuse ``existing`` before generating.
        seed = finding
        if isinstance(finding, Finding) and not finding.result_id and reused_id:
            seed = finding.model_copy(update={"result_id": reused_id})
        result = AssessmentResult.from_finding(seed)

    dims = identity_from_state(
        state,
        framework_id=framework_id or result.framework_id,
        framework_version=framework_version or result.framework_version,
        requirement_id=result.requirement_id,
    )
    # Prefer already-set fields on the result over empty state dims.
    if result.client_id:
        dims["client_id"] = result.client_id
    if result.audit_run_id:
        dims["audit_run_id"] = result.audit_run_id
    if result.asset_id:
        dims["asset_id"] = result.asset_id
    if result.framework_id:
        dims["framework_id"] = result.framework_id
    if result.framework_version:
        dims["framework_version"] = result.framework_version

    if existing is not None:
        if isinstance(existing, AssessmentResult):
            for key in (
                "client_id",
                "audit_run_id",
                "asset_id",
                "framework_id",
                "framework_version",
            ):
                if not dims.get(key):
                    dims[key] = str(getattr(existing, key) or "")
        elif isinstance(existing, Finding):
            for key in (
                "client_id",
                "audit_run_id",
                "asset_id",
                "framework_id",
                "framework_version",
            ):
                if not dims.get(key):
                    dims[key] = str(getattr(existing, key) or "")
        elif isinstance(existing, Mapping):
            for key in (
                "client_id",
                "audit_run_id",
                "asset_id",
                "framework_id",
                "framework_version",
            ):
                if not dims.get(key):
                    dims[key] = str(existing.get(key) or "")

    rid = reused_id or result.result_id or new_result_id()
    identity = ResultIdentity(
        result_id=rid,
        client_id=dims["client_id"],
        audit_run_id=dims["audit_run_id"],
        asset_id=dims["asset_id"],
        framework_id=dims["framework_id"],
        framework_version=dims["framework_version"],
        requirement_id=result.requirement_id or dims["requirement_id"],
    )
    bound = result.model_copy(update={"identity": identity})
    if require_complete:
        validate_result_identity(bound, for_persist=True)
    return bound


def require_persistable(finding: Finding | AssessmentResult) -> AssessmentResult:
    """Validate identity before disk/warehouse write; raise on gaps."""
    result = (
        finding if isinstance(finding, AssessmentResult) else AssessmentResult.from_finding(finding)
    )
    if not result.framework_version:
        raise IncompleteResultIdentityError(
            "framework_version is mandatory before a result can be persisted "
            f"(requirement_id={result.requirement_id!r}, "
            f"framework_id={result.framework_id!r})"
        )
    validate_result_identity(result, for_persist=True)
    return result

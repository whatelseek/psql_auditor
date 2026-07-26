"""Bind CORE-003 identity onto Finding records during assessment."""

from __future__ import annotations

from typing import Any, Mapping

from auditor.domain.result_identity import (
    IncompleteResultIdentityError,
    new_result_id,
    validate_result_identity,
)
from auditor.intake import client_slug
from auditor.state import Finding


def identity_from_state(
    state: Mapping[str, Any] | None,
    *,
    framework_id: str = "",
    framework_version: str = "",
    requirement_id: str = "",
) -> dict[str, str]:
    """Collect identity dimensions from graph state / intake."""
    st = state or {}
    intake = st.get("intake") if isinstance(st.get("intake"), dict) else {}
    client_name = str(st.get("client_name") or intake.get("client_name") or "")
    client_id = str(
        st.get("client_id")
        or intake.get("client_id")
        or (client_slug(client_name) if client_name else "")
        or ""
    ).strip()
    audit_run_id = str(st.get("audit_run_id") or intake.get("audit_run_id") or "").strip()
    intake_state = st.get("intake_state")
    if not audit_run_id and isinstance(intake_state, dict):
        audit_run_id = str(intake_state.get("audit_run_id") or "").strip()
    asset_id = str(st.get("asset_id") or "").strip()
    fw = (framework_id or str(st.get("framework_id") or "")).strip()
    if "/" in fw:
        fw = fw.split("/", 1)[-1]
    ver = (
        framework_version
        or str(st.get("framework_version") or "")
    ).strip()
    return {
        "client_id": client_id,
        "audit_run_id": audit_run_id,
        "asset_id": asset_id,
        "framework_id": fw,
        "framework_version": ver,
        "requirement_id": (requirement_id or "").strip(),
    }


def attach_result_identity(
    finding: Finding,
    *,
    state: Mapping[str, Any] | None = None,
    framework_id: str = "",
    framework_version: str = "",
    existing: Finding | Mapping[str, Any] | None = None,
    require_complete: bool = False,
) -> Finding:
    """Ensure ``finding`` carries result_id + logical key fields.

    Reuses ``result_id`` from ``existing`` when the logical key matches so
    assessment → validation → reporting keep the same physical identity.
    """
    dims = identity_from_state(
        state,
        framework_id=framework_id or finding.framework_id,
        framework_version=framework_version or finding.framework_version,
        requirement_id=finding.requirement_id,
    )
    # Prefer already-set fields on the finding over empty state dims.
    if finding.client_id:
        dims["client_id"] = finding.client_id
    if finding.audit_run_id:
        dims["audit_run_id"] = finding.audit_run_id
    if finding.asset_id:
        dims["asset_id"] = finding.asset_id
    if finding.framework_id:
        dims["framework_id"] = finding.framework_id
    if finding.framework_version:
        dims["framework_version"] = finding.framework_version

    reused_id = ""
    if existing is not None:
        if isinstance(existing, Finding):
            reused_id = existing.result_id
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
            reused_id = str(existing.get("result_id") or "")
            for key in (
                "client_id",
                "audit_run_id",
                "asset_id",
                "framework_id",
                "framework_version",
            ):
                if not dims.get(key):
                    dims[key] = str(existing.get(key) or "")

    finding.client_id = dims["client_id"]
    finding.audit_run_id = dims["audit_run_id"]
    finding.asset_id = dims["asset_id"]
    finding.framework_id = dims["framework_id"]
    finding.framework_version = dims["framework_version"]
    if finding.result_id:
        pass
    elif reused_id:
        finding.result_id = reused_id
    else:
        finding.result_id = new_result_id()

    if require_complete:
        validate_result_identity(finding, for_persist=True)
    return finding


def require_persistable(finding: Finding) -> Finding:
    """Validate identity before disk/warehouse write; raise on gaps."""
    if not finding.framework_version:
        raise IncompleteResultIdentityError(
            "framework_version is mandatory before a result can be persisted "
            f"(requirement_id={finding.requirement_id!r}, "
            f"framework_id={finding.framework_id!r})"
        )
    validate_result_identity(finding, for_persist=True)
    return finding

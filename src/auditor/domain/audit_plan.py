"""Typed audit plan and confirmation gate (INPUT-005).

An audit plan is generated from inventory analysis. Active execution must not
start until the operator explicitly confirms the plan.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
)

from auditor.domain.discovery_plan import DiscoveryPlanStep
from auditor.domain.inventory import (
    FrameworkSelectionDecision,
    TechnologyDetection,
    ValidationIssue,
)

PlanStatus = Literal["draft", "confirmed", "rejected", "superseded"]
PlanAction = Literal[
    "approve",
    "reject",
    "exclude_host",
    "exclude_framework",
    "add_framework",
    "correct_inventory",
    "provide_evidence",
    "mark_exception",
    "reanalyze",
]


class AuditPlanTarget(BaseModel):
    """One host/service audit scope entry."""

    # Not strict: JSON persistence round-trips lists into tuple fields.
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: StrictStr = Field(min_length=1)
    host_id: StrictStr = Field(min_length=1)
    service: StrictStr = ""
    framework_id: StrictStr = Field(min_length=1)
    framework_version: StrictStr = ""
    connection_methods: tuple[StrictStr, ...] = ()
    expected_evidence_sources: tuple[StrictStr, ...] = ()
    limitations: tuple[StrictStr, ...] = ()
    excluded: StrictBool = False


class AuditPlanSummary(BaseModel):
    """Operator-facing counts for confirmation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_hosts: StrictInt
    linux_hosts: StrictInt = 0
    windows_hosts: StrictInt = 0
    postgresql_instances: StrictInt = 0
    total_audit_target_instances: StrictInt
    selected_framework_counts: dict[str, int] = Field(default_factory=dict)
    estimated_coverage: StrictFloat = 0.0
    potentially_destructive: StrictBool = False

    @field_validator("estimated_coverage")
    @classmethod
    def _coverage(cls, value: float) -> float:
        if value < 0.0 or value > 1.0:
            raise ValueError("estimated_coverage must be in [0.0, 1.0]")
        return value


class AuditPlan(BaseModel):
    """Proposed audit scope awaiting operator confirmation."""

    # Not strict: JSON persistence round-trips lists into tuple fields.
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: StrictStr = Field(min_length=1)
    client_id: StrictStr = Field(min_length=1)
    inventory_version_id: StrictStr = Field(min_length=1)
    inventory_content_hash: StrictStr = Field(min_length=1)
    discovery_result_hash: StrictStr = ""
    effective_facts_hash: StrictStr = ""
    preflight_revision_id: StrictStr = ""
    plan_revision_id: StrictStr = ""
    framework_hash: StrictStr = ""
    tool_catalog_hash: StrictStr = ""
    capability_policy_hash: StrictStr = ""
    discovery_plan_id: StrictStr = ""
    discovery_plan_hash: StrictStr = ""
    framework_catalog_hash: StrictStr = ""
    discovery_steps: tuple[DiscoveryPlanStep, ...] = ()
    status: PlanStatus = "draft"
    targets: tuple[AuditPlanTarget, ...] = ()
    framework_decisions: tuple[FrameworkSelectionDecision, ...] = ()
    technology_detections: tuple[TechnologyDetection, ...] = ()
    unresolved_questions: tuple[StrictStr, ...] = ()
    missing_data: tuple[StrictStr, ...] = ()
    validation_issues: tuple[ValidationIssue, ...] = ()
    summary: AuditPlanSummary
    created_at: StrictStr = Field(min_length=1)
    confirmed_at: StrictStr | None = None
    confirmation_note: StrictStr = ""

    @property
    def active_targets(self) -> list[AuditPlanTarget]:
        return [t for t in self.targets if not t.excluded]

    def requires_confirmation(self) -> bool:
        return self.status == "draft"

    def is_executable(self) -> bool:
        return self.status == "confirmed" and bool(self.active_targets)


class PlanConfirmationRequest(BaseModel):
    """Operator decision against a draft audit plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: PlanAction
    host_ids: tuple[StrictStr, ...] = ()
    framework_ids: tuple[StrictStr, ...] = ()
    note: StrictStr = ""


class PlanConfirmationRejected(ValueError):
    """Raised when audit launch is attempted without a confirmed plan."""

    def __init__(self, message: str, *, code: str = "plan_not_confirmed") -> None:
        self.code = code
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self)}

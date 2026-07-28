"""Typed capability discovery plan models (INPUT005-14).

Planning is declarative and secret-free. Steps never carry credentials,
credential references, inventory notes, raw evidence, or tool output.
"""

from __future__ import annotations

from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    field_validator,
    model_validator,
)

DiscoveryStepStatus = Literal[
    "planned",
    "blocked",
    "requires_operator_decision",
]


def _sorted_unique(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(sorted({str(v) for v in values if str(v)}))


class DiscoveryPlanStep(BaseModel):
    """One host-specific discovery proposal (never an executable AuditPlanTarget)."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    step_id: StrictStr = Field(min_length=1)
    host_id: StrictStr = Field(min_length=1)

    capability: StrictStr = Field(min_length=1)
    operation_id: StrictStr = ""
    tool_id: StrictStr = ""

    expected_facts: tuple[StrictStr, ...] = ()
    missing_facts: tuple[StrictStr, ...] = ()

    requested_by_frameworks: tuple[StrictStr, ...] = ()

    status: DiscoveryStepStatus
    reason: StrictStr = Field(min_length=1)

    @field_validator("expected_facts", "missing_facts", "requested_by_frameworks", mode="before")
    @classmethod
    def _normalize_tuples(cls, value: object) -> object:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, (list, tuple)):
            return _sorted_unique(tuple(str(v) for v in value))
        return value

    @model_validator(mode="after")
    def _validate_ids(self) -> DiscoveryPlanStep:
        if self.status == "planned":
            if not self.operation_id or not self.tool_id:
                raise ValueError("planned steps require operation_id and tool_id")
        return self


class CapabilityDiscoveryPlan(BaseModel):
    """Deterministic, confirmation-gated discovery proposal for one inventory."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    discovery_plan_id: StrictStr = Field(min_length=1)
    discovery_plan_hash: StrictStr = Field(min_length=1)

    client_id: StrictStr = Field(min_length=1)
    inventory_version_id: StrictStr = Field(min_length=1)
    inventory_content_hash: StrictStr = Field(min_length=1)

    tool_catalog_hash: StrictStr = ""
    capability_policy_hash: StrictStr = ""

    steps: tuple[DiscoveryPlanStep, ...] = ()
    unresolved_questions: tuple[StrictStr, ...] = ()

    requires_confirmation: StrictBool = True

    @field_validator("unresolved_questions", mode="before")
    @classmethod
    def _normalize_questions(cls, value: object) -> object:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, (list, tuple)):
            # Preserve deterministic order while dropping duplicates.
            seen: set[str] = set()
            out: list[str] = []
            for item in value:
                text = str(item)
                if not text or text in seen:
                    continue
                seen.add(text)
                out.append(text)
            return tuple(out)
        return value

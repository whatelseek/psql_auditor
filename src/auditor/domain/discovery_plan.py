"""Typed capability discovery plan models (INPUT005-14).

Planning is declarative and secret-free. Steps never carry credentials,
credential references, inventory notes, raw evidence, or tool output.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    ValidationInfo,
    field_validator,
    model_validator,
)

from auditor.domain.applicability import (
    validate_capability_id,
    validate_fact_key,
    validate_operation_id,
)

DiscoveryStepStatus = Literal[
    "planned",
    "blocked",
    "requires_operator_decision",
]

_STEP_ID_RE = re.compile(r"^dstep-[0-9a-f]{16}$")
_PLAN_ID_RE = re.compile(r"^dplan-[0-9a-f]{16}$")
_PLAN_HASH_RE = re.compile(r"^dph-[0-9a-f]{16}$")
_FRAMEWORK_IDENTITY_RE = re.compile(r"^[^@\s/\\]+@[^@\s/\\]+$")


def _reject_non_str(value: object, *, field_name: str) -> str:
    """Accept only real strings; never coerce via ``str()`` (secret-safe)."""
    if type(value) is not str:
        raise ValueError(f"{field_name} must be a string")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{field_name} contains control characters")
    return value


def _reject_non_str_sequence(value: object, *, field_name: str) -> tuple[str, ...]:
    """Accept only list/tuple of real strings; never coerce arbitrary objects."""
    if value is None:
        return ()
    if type(value) is str:
        return (_reject_non_str(value, field_name=field_name),)
    if type(value) not in (list, tuple):
        raise ValueError(f"{field_name} must be a list or tuple of strings")
    items = value if isinstance(value, (list, tuple)) else ()
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        item_text = _reject_non_str(item, field_name=field_name)
        if not item_text or item_text in seen:
            continue
        seen.add(item_text)
        out.append(item_text)
    return tuple(sorted(out))


def _reject_questions(value: object) -> tuple[str, ...]:
    """Deduplicate questions while preserving first-seen order."""
    if value is None:
        return ()
    if type(value) is str:
        text = _reject_non_str(value, field_name="unresolved_questions")
        return (text,) if text else ()
    if type(value) not in (list, tuple):
        raise ValueError("unresolved_questions must be a list or tuple of strings")
    items = value if isinstance(value, (list, tuple)) else ()
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        item_text = _reject_non_str(item, field_name="unresolved_questions")
        if not item_text or item_text in seen:
            continue
        seen.add(item_text)
        out.append(item_text)
    return tuple(out)


def _validate_framework_identity(value: str) -> str:
    text = _reject_non_str(value, field_name="requested_by_frameworks")
    if not _FRAMEWORK_IDENTITY_RE.fullmatch(text):
        raise ValueError(
            "requested_by_frameworks entries must be <framework_id>@<framework_version>"
        )
    framework_id, _, framework_version = text.partition("@")
    if not framework_id or not framework_version:
        raise ValueError(
            "requested_by_frameworks entries must be <framework_id>@<framework_version>"
        )
    if "/" in text or "\\" in text:
        raise ValueError("requested_by_frameworks contains path separators")
    return text


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
    capability_options: tuple[StrictStr, ...] = ()
    operation_id: StrictStr = ""
    tool_id: StrictStr = ""

    expected_facts: tuple[StrictStr, ...] = ()
    missing_facts: tuple[StrictStr, ...] = ()

    requested_by_frameworks: tuple[StrictStr, ...] = ()

    status: DiscoveryStepStatus
    reason: StrictStr = Field(min_length=1)

    @field_validator("step_id", mode="before")
    @classmethod
    def _step_id(cls, value: object) -> str:
        text = _reject_non_str(value, field_name="step_id")
        if not _STEP_ID_RE.fullmatch(text):
            raise ValueError("step_id must match dstep-[0-9a-f]{16}")
        return text

    @field_validator("host_id", mode="before")
    @classmethod
    def _host_id(cls, value: object) -> str:
        text = _reject_non_str(value, field_name="host_id")
        if not text.strip():
            raise ValueError("host_id must be a non-empty string")
        if "/" in text or "\\" in text:
            raise ValueError("host_id contains path separators")
        return text

    @field_validator("capability", mode="before")
    @classmethod
    def _capability(cls, value: object) -> str:
        text = _reject_non_str(value, field_name="capability")
        return validate_capability_id(text)

    @field_validator("capability_options", mode="before")
    @classmethod
    def _capability_options(cls, value: object) -> tuple[str, ...]:
        items = _reject_non_str_sequence(value, field_name="capability_options")
        return tuple(validate_capability_id(item) for item in items)

    @field_validator("operation_id", "tool_id", mode="before")
    @classmethod
    def _operation_or_tool(cls, value: object, info: ValidationInfo) -> str:
        text = _reject_non_str(value, field_name=str(info.field_name))
        if text == "":
            return ""
        return validate_operation_id(text)

    @field_validator("expected_facts", "missing_facts", mode="before")
    @classmethod
    def _fact_keys(cls, value: object, info: ValidationInfo) -> tuple[str, ...]:
        items = _reject_non_str_sequence(value, field_name=str(info.field_name))
        return tuple(validate_fact_key(item) for item in items)

    @field_validator("requested_by_frameworks", mode="before")
    @classmethod
    def _frameworks(cls, value: object) -> tuple[str, ...]:
        items = _reject_non_str_sequence(value, field_name="requested_by_frameworks")
        return tuple(_validate_framework_identity(item) for item in items)

    @field_validator("reason", mode="before")
    @classmethod
    def _reason(cls, value: object) -> str:
        text = _reject_non_str(value, field_name="reason")
        if not text.strip():
            raise ValueError("reason must be a non-empty string")
        return text

    @model_validator(mode="after")
    def _validate_ids(self) -> DiscoveryPlanStep:
        if self.status == "planned":
            if not self.operation_id or not self.tool_id:
                raise ValueError("planned steps require operation_id and tool_id")
            if self.operation_id != self.tool_id:
                raise ValueError("planned steps require operation_id == tool_id")
        else:
            if self.operation_id or self.tool_id:
                raise ValueError("non-planned steps must not retain operation/tool identity")
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
    framework_catalog_hash: StrictStr = ""

    tool_catalog_hash: StrictStr = ""
    capability_policy_hash: StrictStr = ""

    steps: tuple[DiscoveryPlanStep, ...] = ()
    unresolved_questions: tuple[StrictStr, ...] = ()

    requires_confirmation: StrictBool = True

    @field_validator(
        "discovery_plan_id",
        "discovery_plan_hash",
        "client_id",
        "inventory_version_id",
        "inventory_content_hash",
        "framework_catalog_hash",
        "tool_catalog_hash",
        "capability_policy_hash",
        mode="before",
    )
    @classmethod
    def _string_fields(cls, value: object, info: ValidationInfo) -> str:
        field_name = str(info.field_name)
        text = _reject_non_str(value, field_name=field_name)
        if field_name == "discovery_plan_id" and not _PLAN_ID_RE.fullmatch(text):
            raise ValueError("discovery_plan_id must match dplan-[0-9a-f]{16}")
        if field_name == "discovery_plan_hash" and not _PLAN_HASH_RE.fullmatch(text):
            raise ValueError("discovery_plan_hash must match dph-[0-9a-f]{16}")
        if (
            field_name
            in {
                "client_id",
                "inventory_version_id",
                "inventory_content_hash",
            }
            and not text.strip()
        ):
            raise ValueError(f"{field_name} must be a non-empty string")
        if "/" in text or "\\" in text:
            if field_name in {
                "discovery_plan_id",
                "discovery_plan_hash",
                "framework_catalog_hash",
                "tool_catalog_hash",
                "capability_policy_hash",
            }:
                raise ValueError(f"{field_name} contains path separators")
        return text

    @field_validator("unresolved_questions", mode="before")
    @classmethod
    def _normalize_questions(cls, value: object) -> tuple[str, ...]:
        return _reject_questions(value)

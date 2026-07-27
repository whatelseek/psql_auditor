"""Safe typed applicability predicates for Markdown frameworks (INPUT-005)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

ApplicabilityOperator = Literal[
    "equals",
    "not_equals",
    "in",
    "not_in",
    "exists",
    "not_exists",
    "contains",
    "greater_than",
    "less_than",
]

PredicateEvalResult = Literal["matched", "not_matched", "missing_evidence", "invalid"]


class ApplicabilityPredicate(BaseModel):
    """One safe comparison against a normalized fact namespace key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fact: StrictStr = Field(min_length=1)
    operator: ApplicabilityOperator
    value: object | None = None

    @model_validator(mode="after")
    def _value_required(self) -> ApplicabilityPredicate:
        if self.operator in {"exists", "not_exists"}:
            return self
        if self.value is None:
            raise ValueError(f"operator {self.operator!r} requires a value")
        if self.operator in {"in", "not_in"} and not isinstance(self.value, (list, tuple, set)):
            raise ValueError(f"operator {self.operator!r} requires a list value")
        return self


class ApplicabilitySpec(BaseModel):
    """Logical groups of predicates: all / any / none."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    all: tuple[ApplicabilityPredicate, ...] = ()
    any: tuple[ApplicabilityPredicate, ...] = ()
    none: tuple[ApplicabilityPredicate, ...] = ()

    @field_validator("all", "any", "none", mode="before")
    @classmethod
    def _coerce_tuple(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, list):
            return tuple(value)
        return value

    def is_empty(self) -> bool:
        return not (self.all or self.any or self.none)


class CapabilityRequirement(BaseModel):
    """Required tool capabilities for a framework."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    any_of: tuple[StrictStr, ...] = ()
    all_of: tuple[StrictStr, ...] = ()

    @field_validator("any_of", "all_of", mode="before")
    @classmethod
    def _coerce(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list):
            return tuple(str(v) for v in value)
        return value

    def is_empty(self) -> bool:
        return not (self.any_of or self.all_of)


class DiscoveryHint(BaseModel):
    """Declarative discovery hint from framework front matter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: StrictStr = Field(min_length=1)
    purpose: StrictStr = ""
    arguments: dict[str, object] = Field(default_factory=dict)
    operation_ids: tuple[StrictStr, ...] = ()
    expected_facts: tuple[StrictStr, ...] = ()

    @field_validator("operation_ids", "expected_facts", mode="before")
    @classmethod
    def _coerce_seq(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, list):
            return tuple(str(v) for v in value)
        return value


class FrameworkApplicabilityMeta(BaseModel):
    """Structured front-matter applicability block for one framework."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    applicability: ApplicabilitySpec = Field(default_factory=ApplicabilitySpec)
    required_capabilities: CapabilityRequirement = Field(default_factory=CapabilityRequirement)
    required_facts: tuple[StrictStr, ...] = ()
    discovery_hints: tuple[DiscoveryHint, ...] = ()
    metadata_valid: bool = True
    validation_errors: tuple[StrictStr, ...] = ()

    @field_validator("required_facts", "discovery_hints", mode="before")
    @classmethod
    def _coerce_seq(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, list):
            return tuple(value)
        return value


def evaluate_predicate(
    predicate: ApplicabilityPredicate,
    facts: dict[str, object],
) -> PredicateEvalResult:
    """Evaluate one predicate against a normalized fact map.

    Unknown facts yield ``missing_evidence`` (never auto-false), except
    ``not_exists`` which matches when the fact is absent.
    """
    key = predicate.fact
    present = key in facts
    raw = facts.get(key)

    try:
        if predicate.operator == "exists":
            return "matched" if present and raw is not None else "missing_evidence"
        if predicate.operator == "not_exists":
            return "matched" if (not present or raw is None) else "not_matched"
        if not present or raw is None:
            return "missing_evidence"

        op = predicate.operator
        expected = predicate.value
        if op == "equals":
            return "matched" if _norm(raw) == _norm(expected) else "not_matched"
        if op == "not_equals":
            return "matched" if _norm(raw) != _norm(expected) else "not_matched"
        if op == "in":
            options = {_norm(v) for v in (expected or [])}  # type: ignore[union-attr]
            return "matched" if _norm(raw) in options else "not_matched"
        if op == "not_in":
            options = {_norm(v) for v in (expected or [])}  # type: ignore[union-attr]
            return "matched" if _norm(raw) not in options else "not_matched"
        if op == "contains":
            return "matched" if str(expected) in str(raw) else "not_matched"
        if op == "greater_than":
            return "matched" if float(raw) > float(expected) else "not_matched"  # type: ignore[arg-type]
        if op == "less_than":
            return "matched" if float(raw) < float(expected) else "not_matched"  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "invalid"
    return "invalid"


def evaluate_applicability(
    spec: ApplicabilitySpec,
    facts: dict[str, object],
) -> tuple[PredicateEvalResult, list[str], list[str]]:
    """Evaluate all/any/none groups.

    Returns ``(result, matched_predicate_labels, missing_fact_keys)``.
    Empty spec matches (framework applies to every host with facts available).
    """
    if spec.is_empty():
        return "matched", [], []

    matched_labels: list[str] = []
    missing: list[str] = []
    saw_invalid = False
    all_failed = False

    def _label(p: ApplicabilityPredicate) -> str:
        return f"{p.fact} {p.operator} {p.value!r}"

    # all — every predicate must match
    for pred in spec.all:
        result = evaluate_predicate(pred, facts)
        if result == "matched":
            matched_labels.append(_label(pred))
        elif result == "missing_evidence":
            missing.append(pred.fact)
        elif result == "invalid":
            saw_invalid = True
        else:
            all_failed = True

    # any — at least one must match (if group non-empty)
    any_matched = False
    any_missing: list[str] = []
    any_saw_definite_miss = False
    if spec.any:
        for pred in spec.any:
            result = evaluate_predicate(pred, facts)
            if result == "matched":
                matched_labels.append(_label(pred))
                any_matched = True
            elif result == "missing_evidence":
                any_missing.append(pred.fact)
            elif result == "invalid":
                saw_invalid = True
                any_saw_definite_miss = True
            else:
                any_saw_definite_miss = True

    # none — no predicate may match; absent facts satisfy "none"
    for pred in spec.none:
        result = evaluate_predicate(pred, facts)
        if result == "matched":
            all_failed = True
        elif result == "missing_evidence":
            matched_labels.append(f"none:{_label(pred)}")
        elif result == "invalid":
            saw_invalid = True
        else:
            matched_labels.append(f"none:{_label(pred)}")

    if saw_invalid:
        return "invalid", matched_labels, sorted(set(missing))
    if all_failed:
        return "not_matched", matched_labels, sorted(set(missing))
    if missing:
        return "missing_evidence", matched_labels, sorted(set(missing))
    if spec.any and not any_matched:
        if any_missing and not any_saw_definite_miss:
            return "missing_evidence", matched_labels, sorted(set(any_missing))
        if any_missing and any_saw_definite_miss:
            # Some alternatives missing, others definitely not matched → missing
            return "missing_evidence", matched_labels, sorted(set(any_missing))
        return "not_matched", matched_labels, []
    return "matched", matched_labels, sorted(set(missing))


def _norm(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip().lower()


def parse_applicability_meta(raw: dict[str, Any] | None) -> FrameworkApplicabilityMeta:
    """Parse structured applicability fields from framework front matter.

    Invalid structured metadata yields ``metadata_valid=False`` with errors
    (framework becomes non-executable for dynamic selection).
    Legacy string ``applicability`` without structured keys yields an empty
    valid spec (caller may synthesize from ``detect:``).
    """
    if not raw:
        return FrameworkApplicabilityMeta()

    errors: list[str] = []
    applicability_raw = raw.get("applicability")
    spec = ApplicabilitySpec()
    if isinstance(applicability_raw, dict):
        try:
            spec = ApplicabilitySpec.model_validate(applicability_raw)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"invalid applicability: {exc}")
    elif isinstance(applicability_raw, str) and applicability_raw.strip():
        # Human-readable legacy string — no structured predicates.
        pass
    elif applicability_raw is not None and not isinstance(applicability_raw, dict):
        errors.append("applicability must be a mapping with all/any/none or a string")

    caps = CapabilityRequirement()
    caps_raw = raw.get("required_capabilities")
    if caps_raw is not None:
        try:
            if isinstance(caps_raw, list):
                caps = CapabilityRequirement(any_of=tuple(str(c) for c in caps_raw))
            else:
                caps = CapabilityRequirement.model_validate(caps_raw)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"invalid required_capabilities: {exc}")

    required_facts: tuple[str, ...] = ()
    facts_raw = raw.get("required_facts")
    if facts_raw is not None:
        if not isinstance(facts_raw, list):
            errors.append("required_facts must be a list of strings")
        else:
            required_facts = tuple(str(f) for f in facts_raw)

    hints: tuple[DiscoveryHint, ...] = ()
    hints_raw = raw.get("discovery_hints")
    if hints_raw is not None:
        if not isinstance(hints_raw, list):
            errors.append("discovery_hints must be a list")
        else:
            parsed_hints: list[DiscoveryHint] = []
            for idx, item in enumerate(hints_raw):
                try:
                    parsed_hints.append(DiscoveryHint.model_validate(item))
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"discovery_hints[{idx}]: {exc}")
            hints = tuple(parsed_hints)

    return FrameworkApplicabilityMeta(
        applicability=spec,
        required_capabilities=caps,
        required_facts=required_facts,
        discovery_hints=hints,
        metadata_valid=not errors,
        validation_errors=tuple(errors),
    )

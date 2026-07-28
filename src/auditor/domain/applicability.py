"""Typed Markdown applicability metadata and safe predicate evaluation.

INPUT005-09 — strict applicability models and parse_applicability_meta.
INPUT005-10 — deterministic predicate / applicability evaluation.

Does not select frameworks. Does not synthesize predicates from legacy ``detect:``.
"""

from __future__ import annotations

import math
import re
from typing import Any, Literal, Mapping

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

ApplicabilityOperator = Literal[
    "equals",
    "not_equals",
    "in",
    "not_in",
    "exists",
    "contains",
    "greater_than",
    "less_than",
]

PredicateResult = Literal[
    "matched",
    "not_matched",
    "missing_evidence",
    "invalid",
]

FactScalar = str | int | float | bool
FactValue = FactScalar | tuple[FactScalar, ...]

FACT_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$")
_CANARY_RE = re.compile(r"CANARY_(?:PASSWORD|TOKEN)_INPUT005_11", re.IGNORECASE)
_RESULT_PRECEDENCE: dict[PredicateResult, int] = {
    "invalid": 0,
    "not_matched": 1,
    "missing_evidence": 2,
    "matched": 3,
}


CAPABILITY_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$")
OPERATION_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")

_STRUCTURED_KEYS = frozenset(
    {
        "required_capabilities",
        "required_facts",
        "discovery_hints",
    }
)


def _reject_dunder_segments(text: str, *, label: str) -> str:
    for segment in text.split("."):
        if (
            not segment
            or segment.startswith("_")
            or segment.endswith("_")
            or "__" in segment
            or "/" in segment
            or "\\" in segment
            or ".." in segment
        ):
            raise ValueError(f"invalid {label}")
    return text


def validate_fact_key(key: str) -> str:
    """Validate a dotted fact key. Central validator for predicates and facts."""
    if not isinstance(key, str):
        raise ValueError("invalid fact key")
    text = key.strip()
    if not FACT_KEY_PATTERN.fullmatch(text):
        raise ValueError("invalid fact key")
    return _reject_dunder_segments(text, label="fact key")


def validate_capability_id(value: str) -> str:
    """Validate a capability ID (same shape as fact keys)."""
    if not isinstance(value, str):
        raise ValueError("invalid capability id")
    text = value.strip()
    if not CAPABILITY_ID_PATTERN.fullmatch(text):
        raise ValueError("invalid capability id")
    return _reject_dunder_segments(text, label="capability id")


def validate_operation_id(value: str) -> str:
    """Validate a discovery operation ID."""
    if not isinstance(value, str):
        raise ValueError("invalid operation id")
    text = value.strip()
    if not OPERATION_ID_PATTERN.fullmatch(text):
        raise ValueError("invalid operation id")
    if text.startswith("_") or text.endswith("_") or "__" in text:
        raise ValueError("invalid operation id")
    return text


def _strict_string_tuple(
    value: object,
    *,
    field_name: str,
    allow_single_string: bool = False,
    item_validator: Any | None = None,
) -> tuple[str, ...]:
    """Coerce a string collection without ``str()`` on arbitrary objects."""
    if value is None:
        return ()
    if isinstance(value, str):
        if not allow_single_string:
            raise ValueError(f"{field_name} must be a list of strings")
        items: list[object] = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise ValueError(f"{field_name} must be a list of strings")

    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} items must be strings")
        text = item.strip()
        if not text:
            raise ValueError(f"{field_name} items must be non-empty strings")
        if item_validator is not None:
            text = item_validator(text)
        out.append(text)
    return tuple(sorted(dict.fromkeys(out)))


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(float(value))


def coerce_fact_value(value: object) -> FactValue:
    """Coerce a fact value or raise ``ValueError`` for unsupported shapes."""
    if value is None:
        raise ValueError("fact value must not be None")
    if callable(value):
        raise ValueError("fact value must not be callable")
    if isinstance(value, Mapping):
        raise ValueError("fact value must not be a mapping")
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("fact value must be a finite number")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        items: list[FactScalar] = []
        for item in value:
            if isinstance(item, (list, tuple, Mapping)) or item is None or callable(item):
                raise ValueError("fact value tuple must contain only scalars")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("fact value must be a finite number")
            if isinstance(item, bool):
                items.append(item)
            elif isinstance(item, (int, float, str)):
                items.append(item)
            else:
                raise ValueError("fact value tuple must contain only scalars")
        return tuple(items)
    raise ValueError(f"unsupported fact value type: {type(value).__name__}")


def _sanitize_error(message: str) -> str:
    text = _CANARY_RE.sub("[redacted]", str(message))
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 240:
        text = text[:240] + "..."
    return text or "invalid applicability metadata"


def _norm_str(value: object) -> str:
    return str(value).strip().lower()


class ApplicabilityPredicate(BaseModel):
    """One safe comparison against a normalized fact namespace key."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    fact: StrictStr = Field(min_length=1)
    operator: ApplicabilityOperator
    value: FactValue | None = None

    @field_validator("fact")
    @classmethod
    def _fact_key(cls, value: str) -> str:
        return validate_fact_key(value)

    @field_validator("value", mode="before")
    @classmethod
    def _coerce_value(cls, value: Any) -> Any:
        if value is None:
            return None
        return coerce_fact_value(value)

    @model_validator(mode="after")
    def _operator_value_rules(self) -> ApplicabilityPredicate:
        op = self.operator
        val = self.value
        if op == "exists":
            if val is not None:
                raise ValueError("operator 'exists' must not define a value")
            return self
        if val is None:
            raise ValueError(f"operator {op!r} requires a value")
        if op in {"equals", "not_equals", "contains"}:
            if isinstance(val, tuple):
                raise ValueError(f"operator {op!r} requires one scalar value")
            return self
        if op in {"in", "not_in"}:
            if not isinstance(val, tuple) or not val:
                raise ValueError(f"operator {op!r} requires a non-empty list of scalars")
            return self
        if op in {"greater_than", "less_than"}:
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise ValueError(f"operator {op!r} requires an integer or float value")
            if isinstance(val, float) and not math.isfinite(val):
                raise ValueError(f"operator {op!r} requires a finite number")
            return self
        raise ValueError(f"unsupported operator: {op!r}")


class ApplicabilitySpec(BaseModel):
    """Logical groups of predicates: all / any / none."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

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

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    any_of: tuple[StrictStr, ...] = ()
    all_of: tuple[StrictStr, ...] = ()

    @field_validator("any_of", "all_of", mode="before")
    @classmethod
    def _coerce(cls, value: Any, info: ValidationInfo) -> Any:
        return _strict_string_tuple(
            value,
            field_name=str(info.field_name),
            allow_single_string=True,
            item_validator=validate_capability_id,
        )

    def is_empty(self) -> bool:
        return not (self.any_of or self.all_of)


class DiscoveryHint(BaseModel):
    """Declarative discovery hint from framework front matter."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    capability: StrictStr = Field(min_length=1)
    purpose: StrictStr = ""
    operation_ids: tuple[StrictStr, ...] = ()
    expected_facts: tuple[StrictStr, ...] = ()

    @field_validator("capability")
    @classmethod
    def _capability(cls, value: str) -> str:
        return validate_capability_id(value)

    @field_validator("operation_ids", mode="before")
    @classmethod
    def _coerce_ops(cls, value: Any) -> Any:
        return _strict_string_tuple(
            value,
            field_name="operation_ids",
            allow_single_string=True,
            item_validator=validate_operation_id,
        )

    @field_validator("expected_facts", mode="before")
    @classmethod
    def _coerce_facts(cls, value: Any) -> Any:
        return _strict_string_tuple(
            value,
            field_name="expected_facts",
            allow_single_string=True,
            item_validator=validate_fact_key,
        )


class FrameworkApplicabilityMeta(BaseModel):
    """Structured front-matter applicability block for one framework."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    applicability: ApplicabilitySpec = Field(default_factory=ApplicabilitySpec)
    required_capabilities: CapabilityRequirement = Field(default_factory=CapabilityRequirement)
    required_facts: tuple[StrictStr, ...] = ()
    discovery_hints: tuple[DiscoveryHint, ...] = ()
    has_structured_applicability: bool = False
    metadata_valid: bool = True
    validation_errors: tuple[StrictStr, ...] = ()

    @field_validator("required_facts", mode="before")
    @classmethod
    def _coerce_facts(cls, value: Any) -> Any:
        return _strict_string_tuple(
            value,
            field_name="required_facts",
            allow_single_string=False,
            item_validator=validate_fact_key,
        )

    @field_validator("discovery_hints", mode="before")
    @classmethod
    def _coerce_hints(cls, value: Any) -> Any:
        if value is None:
            return ()
        if isinstance(value, tuple):
            return value
        if isinstance(value, list):
            return tuple(value)
        raise ValueError("discovery_hints must be a list")


class ApplicabilityEvaluation(BaseModel):
    """Deterministic result of evaluating an :class:`ApplicabilitySpec`."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    result: PredicateResult
    matched_fact_keys: tuple[str, ...] = ()
    missing_facts: tuple[str, ...] = ()
    invalid_predicates: tuple[str, ...] = ()


def _predicate_label(predicate: ApplicabilityPredicate) -> str:
    if predicate.value is None:
        return f"{predicate.fact} {predicate.operator}"
    return f"{predicate.fact} {predicate.operator}"


def evaluate_predicate(
    predicate: ApplicabilityPredicate,
    facts: Mapping[str, FactValue],
) -> PredicateResult:
    """Evaluate one predicate. Absent facts always yield ``missing_evidence``."""
    key = predicate.fact
    if key not in facts:
        return "missing_evidence"

    raw = facts[key]
    op = predicate.operator
    expected = predicate.value

    try:
        if op == "exists":
            return "matched"

        if op == "equals":
            assert expected is not None and not isinstance(expected, tuple)
            if isinstance(raw, tuple) or isinstance(expected, tuple):
                return "invalid"
            if isinstance(raw, str) or isinstance(expected, str):
                return "matched" if _norm_str(raw) == _norm_str(expected) else "not_matched"
            return "matched" if raw == expected else "not_matched"

        if op == "not_equals":
            assert expected is not None and not isinstance(expected, tuple)
            if isinstance(raw, tuple) or isinstance(expected, tuple):
                return "invalid"
            if isinstance(raw, str) or isinstance(expected, str):
                return "matched" if _norm_str(raw) != _norm_str(expected) else "not_matched"
            return "matched" if raw != expected else "not_matched"

        if op == "in":
            assert isinstance(expected, tuple) and expected
            if isinstance(raw, tuple):
                return "invalid"
            if isinstance(raw, str):
                options = {_norm_str(v) for v in expected}
                return "matched" if _norm_str(raw) in options else "not_matched"
            options_raw = set(expected)
            # casefold string options for mixed compares
            if any(isinstance(v, str) for v in expected) or isinstance(raw, str):
                options = {_norm_str(v) for v in expected}
                return "matched" if _norm_str(raw) in options else "not_matched"
            return "matched" if raw in options_raw else "not_matched"

        if op == "not_in":
            assert isinstance(expected, tuple) and expected
            if isinstance(raw, tuple):
                return "invalid"
            if isinstance(raw, str) or any(isinstance(v, str) for v in expected):
                options = {_norm_str(v) for v in expected}
                return "matched" if _norm_str(raw) not in options else "not_matched"
            return "matched" if raw not in set(expected) else "not_matched"

        if op == "contains":
            assert expected is not None and not isinstance(expected, tuple)
            if isinstance(raw, str) and isinstance(expected, str):
                return "matched" if expected.lower() in raw.lower() else "not_matched"
            if isinstance(raw, tuple):
                if isinstance(expected, str):
                    return (
                        "matched"
                        if any(
                            isinstance(item, str) and _norm_str(item) == _norm_str(expected)
                            for item in raw
                        )
                        or any(item == expected for item in raw if not isinstance(item, str))
                        else "not_matched"
                    )
                return "matched" if expected in raw else "not_matched"
            return "invalid"

        if op in {"greater_than", "less_than"}:
            assert expected is not None
            if isinstance(raw, bool) or isinstance(expected, bool):
                return "invalid"
            if not _is_finite_number(raw) or not _is_finite_number(expected):
                return "invalid"
            left = float(raw)  # type: ignore[arg-type]
            right = float(expected)  # type: ignore[arg-type]
            if op == "greater_than":
                return "matched" if left > right else "not_matched"
            return "matched" if left < right else "not_matched"
    except (TypeError, ValueError, AssertionError):
        return "invalid"
    return "invalid"


def _merge_eval_parts(
    parts: list[ApplicabilityEvaluation],
) -> ApplicabilityEvaluation:
    if not parts:
        return ApplicabilityEvaluation(result="matched")
    best = parts[0].result
    for part in parts[1:]:
        if _RESULT_PRECEDENCE[part.result] < _RESULT_PRECEDENCE[best]:
            best = part.result
    matched = tuple(sorted({k for p in parts for k in p.matched_fact_keys}))
    missing = tuple(sorted({k for p in parts for k in p.missing_facts}))
    invalid = tuple(sorted({k for p in parts for k in p.invalid_predicates}))
    return ApplicabilityEvaluation(
        result=best,
        matched_fact_keys=matched,
        missing_facts=missing,
        invalid_predicates=invalid,
    )


def _eval_all(
    predicates: tuple[ApplicabilityPredicate, ...],
    facts: Mapping[str, FactValue],
) -> ApplicabilityEvaluation:
    matched_keys: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []
    saw_not_matched = False
    for pred in predicates:
        result = evaluate_predicate(pred, facts)
        label = _predicate_label(pred)
        if result == "invalid":
            invalid.append(label)
        elif result == "not_matched":
            saw_not_matched = True
        elif result == "missing_evidence":
            missing.append(pred.fact)
        elif result == "matched":
            matched_keys.append(pred.fact)
    if invalid:
        return ApplicabilityEvaluation(
            result="invalid",
            matched_fact_keys=tuple(sorted(set(matched_keys))),
            missing_facts=tuple(sorted(set(missing))),
            invalid_predicates=tuple(sorted(set(invalid))),
        )
    if saw_not_matched:
        return ApplicabilityEvaluation(
            result="not_matched",
            matched_fact_keys=tuple(sorted(set(matched_keys))),
            missing_facts=tuple(sorted(set(missing))),
        )
    if missing:
        return ApplicabilityEvaluation(
            result="missing_evidence",
            matched_fact_keys=tuple(sorted(set(matched_keys))),
            missing_facts=tuple(sorted(set(missing))),
        )
    return ApplicabilityEvaluation(
        result="matched",
        matched_fact_keys=tuple(sorted(set(matched_keys))),
    )


def _eval_any(
    predicates: tuple[ApplicabilityPredicate, ...],
    facts: Mapping[str, FactValue],
) -> ApplicabilityEvaluation:
    matched_keys: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []
    saw_matched = False
    for pred in predicates:
        result = evaluate_predicate(pred, facts)
        label = _predicate_label(pred)
        if result == "invalid":
            invalid.append(label)
        elif result == "matched":
            saw_matched = True
            matched_keys.append(pred.fact)
        elif result == "missing_evidence":
            missing.append(pred.fact)
    if invalid:
        return ApplicabilityEvaluation(
            result="invalid",
            matched_fact_keys=tuple(sorted(set(matched_keys))),
            missing_facts=tuple(sorted(set(missing))),
            invalid_predicates=tuple(sorted(set(invalid))),
        )
    if saw_matched:
        return ApplicabilityEvaluation(
            result="matched",
            matched_fact_keys=tuple(sorted(set(matched_keys))),
            missing_facts=tuple(sorted(set(missing))),
        )
    if missing:
        return ApplicabilityEvaluation(
            result="missing_evidence",
            missing_facts=tuple(sorted(set(missing))),
        )
    return ApplicabilityEvaluation(result="not_matched")


def _eval_none(
    predicates: tuple[ApplicabilityPredicate, ...],
    facts: Mapping[str, FactValue],
) -> ApplicabilityEvaluation:
    matched_keys: list[str] = []
    missing: list[str] = []
    invalid: list[str] = []
    saw_matched = False
    for pred in predicates:
        result = evaluate_predicate(pred, facts)
        label = _predicate_label(pred)
        if result == "invalid":
            invalid.append(label)
        elif result == "matched":
            saw_matched = True
            matched_keys.append(pred.fact)
        elif result == "missing_evidence":
            missing.append(pred.fact)
    if invalid:
        return ApplicabilityEvaluation(
            result="invalid",
            matched_fact_keys=tuple(sorted(set(matched_keys))),
            missing_facts=tuple(sorted(set(missing))),
            invalid_predicates=tuple(sorted(set(invalid))),
        )
    if saw_matched:
        return ApplicabilityEvaluation(
            result="not_matched",
            matched_fact_keys=tuple(sorted(set(matched_keys))),
            missing_facts=tuple(sorted(set(missing))),
        )
    if missing:
        return ApplicabilityEvaluation(
            result="missing_evidence",
            missing_facts=tuple(sorted(set(missing))),
        )
    return ApplicabilityEvaluation(result="matched")


def evaluate_applicability(
    spec: ApplicabilitySpec,
    facts: Mapping[str, FactValue],
) -> ApplicabilityEvaluation:
    """Evaluate all/any/none groups with combined precedence."""
    if spec.is_empty():
        return ApplicabilityEvaluation(result="matched")

    parts: list[ApplicabilityEvaluation] = []
    if spec.all:
        parts.append(_eval_all(spec.all, facts))
    if spec.any:
        parts.append(_eval_any(spec.any, facts))
    if spec.none:
        parts.append(_eval_none(spec.none, facts))
    return _merge_eval_parts(parts)


def _detect_structured(raw: Mapping[str, object]) -> bool:
    """Presence-based structured metadata detection (fail closed)."""
    if any(key in raw for key in _STRUCTURED_KEYS):
        return True
    if "applicability" not in raw:
        return False
    applicability = raw.get("applicability")
    if isinstance(applicability, Mapping):
        return True
    if isinstance(applicability, str):
        return False
    # Non-mapping, non-string applicability (list/int/bool/...) is structured-invalid.
    return True


def parse_applicability_meta(
    raw_front_matter: Mapping[str, object] | None,
) -> FrameworkApplicabilityMeta:
    """Parse optional structured applicability metadata from framework front matter.

    Legacy frameworks (no structured block) remain valid with
    ``has_structured_applicability=False``. Invalid structured metadata never
    raises — it returns ``metadata_valid=False`` with sanitized errors.
    """
    if not raw_front_matter:
        return FrameworkApplicabilityMeta()

    if not _detect_structured(raw_front_matter):
        return FrameworkApplicabilityMeta(has_structured_applicability=False, metadata_valid=True)

    try:
        app_raw = raw_front_matter.get("applicability")
        if app_raw is None:
            applicability = ApplicabilitySpec()
        elif isinstance(app_raw, Mapping):
            allowed = {"all", "any", "none"}
            unknown = set(app_raw.keys()) - allowed
            if unknown:
                raise ValueError("unknown applicability fields")
            applicability = ApplicabilitySpec.model_validate(app_raw)
        else:
            raise ValueError("applicability must be a mapping when structured")

        caps_raw = raw_front_matter.get("required_capabilities")
        if caps_raw is None:
            caps = CapabilityRequirement()
        elif isinstance(caps_raw, Mapping):
            allowed_c = {"any_of", "all_of"}
            unknown_c = set(caps_raw.keys()) - allowed_c
            if unknown_c:
                raise ValueError("unknown required_capabilities fields")
            caps = CapabilityRequirement.model_validate(caps_raw)
        else:
            raise ValueError("required_capabilities must be a mapping")

        facts_raw = raw_front_matter.get("required_facts")
        if "required_facts" in raw_front_matter:
            required_facts = _strict_string_tuple(
                facts_raw,
                field_name="required_facts",
                allow_single_string=False,
                item_validator=validate_fact_key,
            )
        else:
            required_facts = ()

        hints_raw = raw_front_matter.get("discovery_hints")
        if hints_raw is None:
            hints: tuple[DiscoveryHint, ...] = ()
        elif isinstance(hints_raw, list):
            hints = tuple(DiscoveryHint.model_validate(item) for item in hints_raw)
        else:
            raise ValueError("discovery_hints must be a list")

        return FrameworkApplicabilityMeta(
            applicability=applicability,
            required_capabilities=caps,
            required_facts=required_facts,
            discovery_hints=hints,
            has_structured_applicability=True,
            metadata_valid=True,
            validation_errors=(),
        )
    except (ValidationError, ValueError, TypeError) as exc:
        if isinstance(exc, ValidationError):
            errors = tuple(
                sorted(
                    {
                        _sanitize_error(err.get("msg", "invalid applicability metadata"))
                        for err in exc.errors()
                    }
                )
            )
        else:
            errors = (_sanitize_error(str(exc)),)
        return FrameworkApplicabilityMeta(
            has_structured_applicability=True,
            metadata_valid=False,
            validation_errors=errors or (_sanitize_error("invalid applicability metadata"),),
        )

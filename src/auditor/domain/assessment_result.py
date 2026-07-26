"""Canonical structured assessment result (CORE-004).

``AssessmentResult`` is the single typed contract for workflow state,
persistence, and serialization. :class:`~auditor.state.Finding` is retained
only as a report-oriented adapter (``observation``→``evidence``,
``recommendation``→``remediation``).
"""

from __future__ import annotations

from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from auditor.domain.result_identity import (
    IncompleteResultIdentityError,
    ResultLogicalKey,
    new_result_id,
    validate_result_identity,
)

AssessmentStatus = Literal[
    "pass",
    "fail",
    "partial",
    "error",
    "skipped",
    "not_tested",
    "not_applicable",
    "accepted_exception",
]

SUPPORTED_ASSESSMENT_STATUSES: frozenset[str] = frozenset(
    {
        "pass",
        "fail",
        "partial",
        "error",
        "skipped",
        "not_tested",
        "not_applicable",
        "accepted_exception",
    }
)

# Statuses that may carry a structured execution error.
_ERROR_CAPABLE_STATUSES: frozenset[str] = frozenset({"error"})


class ResultIdentity(BaseModel):
    """Physical + logical identity from CORE-003."""

    result_id: str
    client_id: str
    audit_run_id: str
    asset_id: str
    framework_id: str
    framework_version: str
    requirement_id: str

    @field_validator(
        "result_id",
        "client_id",
        "audit_run_id",
        "asset_id",
        "framework_id",
        "framework_version",
        "requirement_id",
        mode="before",
    )
    @classmethod
    def _strip_str(cls, value: Any) -> str:
        return str(value or "").strip()

    @field_validator("result_id")
    @classmethod
    def _valid_uuid(cls, value: str) -> str:
        if not value:
            raise ValueError("result_id is required")
        try:
            UUID(value)
        except ValueError as exc:
            raise ValueError(f"result_id must be a UUID string, got {value!r}") from exc
        return value

    def logical_key(self) -> ResultLogicalKey:
        return ResultLogicalKey(
            client_id=self.client_id,
            audit_run_id=self.audit_run_id,
            asset_id=self.asset_id,
            framework_id=self.framework_id,
            framework_version=self.framework_version,
            requirement_id=self.requirement_id,
        )

    def as_flat_dict(self) -> dict[str, str]:
        return {
            "result_id": self.result_id,
            "client_id": self.client_id,
            "audit_run_id": self.audit_run_id,
            "asset_id": self.asset_id,
            "framework_id": self.framework_id,
            "framework_version": self.framework_version,
            "requirement_id": self.requirement_id,
        }


class EvidenceRef(BaseModel):
    """Reference to supporting evidence (tool log, file, or URL)."""

    kind: str = "tool"
    uri: str = ""
    label: str = ""
    tool_name: str = ""

    @field_validator("kind", "uri", "label", "tool_name", mode="before")
    @classmethod
    def _strip_str(cls, value: Any) -> str:
        return str(value or "").strip()


class AssessmentError(BaseModel):
    """Structured execution / validation error (not free-text in observation)."""

    error_type: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("error_type", "message", mode="before")
    @classmethod
    def _strip_str(cls, value: Any) -> str:
        return str(value or "").strip()

    @classmethod
    def from_exception(cls, exc: BaseException) -> AssessmentError:
        return cls(error_type=type(exc).__name__, message=str(exc))

    @classmethod
    def malformed_model_output(cls, detail: str = "") -> AssessmentError:
        return cls(
            error_type="MalformedModelOutput",
            message="LLM output could not be validated into AssessmentResult",
            details={"detail": detail} if detail else {},
        )


class AssessmentResult(BaseModel):
    """Canonical typed assessment result for workflow, persistence, and APIs."""

    identity: ResultIdentity
    status: AssessmentStatus
    observation: str = ""
    recommendation: str = ""
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    error: AssessmentError | None = None
    # Checklist metadata carried for reporting (not part of logical identity).
    title: str = ""
    severity: str = ""
    category: str = ""
    pass_criteria: str = ""
    notes: str = ""

    @field_validator(
        "observation",
        "recommendation",
        "title",
        "severity",
        "category",
        "pass_criteria",
        "notes",
        mode="before",
    )
    @classmethod
    def _coerce_str(cls, value: Any) -> str:
        return "" if value is None else str(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _coerce_refs(cls, value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        raise TypeError("evidence_refs must be a list")

    @field_validator("status", mode="before")
    @classmethod
    def _validate_status(cls, value: Any) -> str:
        status = str(value or "").strip().lower()
        if status not in SUPPORTED_ASSESSMENT_STATUSES:
            raise ValueError(
                f"unsupported assessment status {value!r}; "
                f"allowed={sorted(SUPPORTED_ASSESSMENT_STATUSES)}"
            )
        return status

    @model_validator(mode="after")
    def _error_consistency(self) -> AssessmentResult:
        if self.error is not None and self.status not in _ERROR_CAPABLE_STATUSES:
            raise ValueError(
                f"status {self.status!r} cannot carry AssessmentError; "
                "only status='error' may include structured error state"
            )
        return self

    # --- identity accessors (duck-type compatible with Finding / maps) --------

    @property
    def result_id(self) -> str:
        return self.identity.result_id

    @property
    def client_id(self) -> str:
        return self.identity.client_id

    @property
    def audit_run_id(self) -> str:
        return self.identity.audit_run_id

    @property
    def asset_id(self) -> str:
        return self.identity.asset_id

    @property
    def framework_id(self) -> str:
        return self.identity.framework_id

    @property
    def framework_version(self) -> str:
        return self.identity.framework_version

    @property
    def requirement_id(self) -> str:
        return self.identity.requirement_id

    def logical_key(self) -> ResultLogicalKey:
        return self.identity.logical_key()

    def ensure_persistable(self) -> AssessmentResult:
        """Validate full identity before disk/warehouse write."""
        validate_result_identity(self, for_persist=True)
        return self

    def with_correction(
        self,
        *,
        status: AssessmentStatus | None = None,
        observation: str | None = None,
        recommendation: str | None = None,
        evidence_refs: list[EvidenceRef] | None = None,
        error: AssessmentError | None | object = ...,
        notes: str | None = None,
    ) -> AssessmentResult:
        """Return a corrected copy that preserves identity fields unchanged."""
        data = self.model_dump()
        if status is not None:
            data["status"] = status
        if observation is not None:
            data["observation"] = observation
        if recommendation is not None:
            data["recommendation"] = recommendation
        if evidence_refs is not None:
            data["evidence_refs"] = evidence_refs
        if notes is not None:
            data["notes"] = notes
        if error is not ...:
            data["error"] = error
        # Identity is reconstructed from the same nested dict — never rewritten here.
        corrected = AssessmentResult.model_validate(data)
        if corrected.identity.model_dump() != self.identity.model_dump():
            raise RuntimeError("correction mutated result identity")
        return corrected

    def to_finding(self) -> Any:
        """One-way report adapter → :class:`~auditor.state.Finding`.

        Maps ``observation``→``evidence`` and ``recommendation``→``remediation``.
        """
        from auditor.state import Finding

        return Finding(
            requirement_id=self.requirement_id,
            title=self.title,
            status=self.status,
            severity=self.severity,
            category=self.category,
            evidence=self.observation,
            remediation=self.recommendation,
            notes=self.notes,
            pass_criteria=self.pass_criteria,
            result_id=self.result_id,
            client_id=self.client_id,
            audit_run_id=self.audit_run_id,
            asset_id=self.asset_id,
            framework_id=self.framework_id,
            framework_version=self.framework_version,
        )

    @classmethod
    def from_finding(cls, finding: Any) -> AssessmentResult:
        """Temporary one-way compatibility conversion from legacy Finding/dict.

        Accepts legacy ``evidence`` / ``remediation`` field names and maps them
        to ``observation`` / ``recommendation``. Does not write those aliases
        back onto the canonical model.
        """
        if isinstance(finding, cls):
            return finding
        if hasattr(finding, "model_dump"):
            data = finding.model_dump()
        elif isinstance(finding, Mapping):
            data = dict(finding)
        else:
            raise TypeError(f"cannot convert {type(finding)!r} to AssessmentResult")

        if data.get("observation") is not None:
            observation = str(data.get("observation"))
        else:
            observation = str(data.get("evidence") or "")
        recommendation = str(
            data.get("recommendation")
            if data.get("recommendation") is not None
            else data.get("remediation") or ""
        )
        rid = str(data.get("result_id") or "").strip() or new_result_id()
        identity = ResultIdentity(
            result_id=rid,
            client_id=str(data.get("client_id") or "").strip(),
            audit_run_id=str(data.get("audit_run_id") or "").strip(),
            asset_id=str(data.get("asset_id") or "").strip(),
            framework_id=str(data.get("framework_id") or "").strip(),
            framework_version=str(data.get("framework_version") or "").strip(),
            requirement_id=str(data.get("requirement_id") or data.get("req_id") or "").strip(),
        )
        status = str(data.get("status") or "error").strip().lower()
        if status not in SUPPORTED_ASSESSMENT_STATUSES:
            raise ValueError(f"unsupported assessment status {status!r}")
        err_raw = data.get("error")
        error: AssessmentError | None = None
        if err_raw is not None:
            error = AssessmentError.model_validate(err_raw)
        refs_raw = data.get("evidence_refs") or []
        return cls(
            identity=identity,
            status=status,  # type: ignore[arg-type]
            observation=observation,
            recommendation=recommendation,
            evidence_refs=[EvidenceRef.model_validate(r) for r in refs_raw],
            error=error,
            title=str(data.get("title") or ""),
            severity=str(data.get("severity") or ""),
            category=str(data.get("category") or ""),
            pass_criteria=str(data.get("pass_criteria") or ""),
            notes=str(data.get("notes") or ""),
        )

    @classmethod
    def from_llm_payload(
        cls,
        payload: Mapping[str, Any] | None,
        *,
        identity: ResultIdentity,
        title: str = "",
        severity: str = "",
        category: str = "",
        pass_criteria: str = "",
        fallback_observation: str = "",
    ) -> AssessmentResult:
        """Validate LLM JSON cells into AssessmentResult.

        Malformed / missing payload yields a controlled ``status=error`` result
        with structured :class:`AssessmentError` — never a partially valid row.
        """
        if not isinstance(payload, Mapping):
            return cls(
                identity=identity,
                status="error",
                observation=fallback_observation or "",
                recommendation="",
                evidence_refs=[],
                error=AssessmentError.malformed_model_output("missing or non-object JSON"),
                title=title,
                severity=severity,
                category=category,
                pass_criteria=pass_criteria,
            )
        try:
            status_raw = str(payload.get("status") or "").strip().lower()
            if status_raw not in SUPPORTED_ASSESSMENT_STATUSES:
                raise ValueError(f"unsupported status {payload.get('status')!r}")
            observation = str(
                payload.get("observation")
                if payload.get("observation") is not None
                else payload.get("evidence")
                if payload.get("evidence") is not None
                else fallback_observation or ""
            )
            recommendation = str(
                payload.get("recommendation")
                if payload.get("recommendation") is not None
                else payload.get("remediation") or ""
            )
            refs_raw = payload.get("evidence_refs")
            if refs_raw is None:
                refs: list[EvidenceRef] = []
            elif isinstance(refs_raw, list):
                refs = [EvidenceRef.model_validate(r) for r in refs_raw]
            else:
                raise TypeError("evidence_refs must be a list")
            return cls(
                identity=identity,
                status=status_raw,  # type: ignore[arg-type]
                observation=observation,
                recommendation=recommendation,
                evidence_refs=refs,
                error=None,
                title=title,
                severity=severity,
                category=category,
                pass_criteria=pass_criteria,
                notes=str(payload.get("notes") or ""),
            )
        except Exception as exc:  # noqa: BLE001 — controlled validation boundary
            return cls(
                identity=identity,
                status="error",
                observation=fallback_observation or "",
                recommendation="",
                evidence_refs=[],
                error=AssessmentError.malformed_model_output(str(exc)),
                title=title,
                severity=severity,
                category=category,
                pass_criteria=pass_criteria,
            )

    def to_persist_dict(self) -> dict[str, Any]:
        """Serialize for evidence/warehouse JSON using canonical field names."""
        data = self.model_dump()
        flat = self.identity.as_flat_dict()
        data.update(flat)
        # Do not emit legacy evidence/remediation aliases.
        return data

    @classmethod
    def from_persist_dict(cls, data: Mapping[str, Any]) -> AssessmentResult:
        """Load from disk/warehouse JSON; map legacy aliases once if present."""
        payload = dict(data)
        if "identity" not in payload:
            # Flat persistence layout (common for finding.json).
            return cls.from_finding(payload)
        return cls.model_validate(payload)


def require_assessment_result(value: Any) -> AssessmentResult:
    """Coerce Finding/dict/AssessmentResult; reject incomplete for persistence."""
    result = value if isinstance(value, AssessmentResult) else AssessmentResult.from_finding(value)
    try:
        result.ensure_persistable()
    except IncompleteResultIdentityError:
        raise
    return result

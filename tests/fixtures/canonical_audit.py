"""Canonical deterministic audit scenario (AUD-003).

Builds an immutable, fixed-ID dataset for workflow / history / reporting /
exception / persistence tests. Construction never reads wall-clock time, never
calls ``uuid4()``, and never opens network sockets.

Extend this module when later tasks need additional cases — do not fork a second
incompatible dataset.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Mapping
from uuid import UUID

from auditor.checklist import Requirement
from auditor.client_registry import Client
from auditor.clock import FixedClock
from auditor.domain.audit_models import AuditRun, AuditRunStatus
from auditor.domain.result_identity import (
    historical_comparison_key,
    is_historically_comparable,
)
from auditor.state import Finding, FindingStatus
from auditor.testing.fake_llm import DeterministicFakeChatModel

# ---------------------------------------------------------------------------
# Fixed clock
# ---------------------------------------------------------------------------

FIXED_NOW = datetime(2026, 7, 26, 9, 0, 0, tzinfo=timezone.utc)
FIXED_CLOCK = FixedClock(FIXED_NOW)

# ---------------------------------------------------------------------------
# Fixed identifiers (literal — never generated at runtime)
# ---------------------------------------------------------------------------

CLIENT_ALPHA_ID = "client_alpha0000001a"
CLIENT_BETA_ID = "client_beta00000001b"

RUN_ALPHA_PREVIOUS_ID = "arun_alpha_prev00001"
RUN_ALPHA_CURRENT_ID = "arun_alpha_curr00001"
RUN_BETA_CURRENT_ID = "arun_beta_curr000001"

ASSET_LINUX_01_ID = "aaaaaaaa-1111-4111-8111-111111111111"
ASSET_LINUX_02_ID = "aaaaaaaa-2222-4222-8222-222222222222"
ASSET_BETA_01_ID = "bbbbbbbb-1111-4111-8111-111111111111"

FRAMEWORK_LINUX_ID = "framework_linux"
FRAMEWORK_POSTGRESQL_ID = "framework_postgresql"
FRAMEWORK_VERSION = "1.0.0"

RESULT_PASS_ID = "a0000001-0001-4001-8001-000000000001"
RESULT_FAIL_ID = "a0000001-0001-4001-8001-000000000002"
RESULT_PARTIAL_ID = "a0000001-0001-4001-8001-000000000003"
RESULT_ERROR_ID = "a0000001-0001-4001-8001-000000000004"
RESULT_NOT_TESTED_ID = "a0000001-0001-4001-8001-000000000005"
RESULT_NOT_APPLICABLE_ID = "a0000001-0001-4001-8001-000000000006"
RESULT_ACCEPTED_EXCEPTION_ID = "a0000001-0001-4001-8001-000000000007"
RESULT_PREVIOUS_COMPARABLE_ID = "a0000001-0001-4001-8001-000000000008"
RESULT_PREVIOUS_NONCOMPARABLE_ID = "a0000001-0001-4001-8001-000000000009"
RESULT_FORMULA_EQ_ID = "a0000001-0001-4001-8001-00000000000a"
RESULT_FORMULA_PLUS_ID = "a0000001-0001-4001-8001-00000000000b"
RESULT_FORMULA_MINUS_ID = "a0000001-0001-4001-8001-00000000000c"
RESULT_FORMULA_AT_ID = "a0000001-0001-4001-8001-00000000000d"
RESULT_RU_OBS_ID = "a0000001-0001-4001-8001-00000000000e"
RESULT_EN_OBS_ID = "a0000001-0001-4001-8001-00000000000f"
RESULT_LONG_OBS_ID = "a0000001-0001-4001-8001-000000000010"

EXCEPTION_ACTIVE_ID = UUID("e0000001-0001-4001-8001-000000000001")
EXCEPTION_EXPIRED_ID = UUID("e0000001-0001-4001-8001-000000000002")
EXCEPTION_REVOKED_ID = UUID("e0000001-0001-4001-8001-000000000003")

TS_ALPHA_PREVIOUS = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
TS_ALPHA_CURRENT = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
TS_BETA_CURRENT = datetime(2026, 7, 22, 8, 30, 0, tzinfo=timezone.utc)

# Long observation: fixed seed × fixed count (asserted in tests).
_LONG_OBS_UNIT = "Уникод-блок-αβγ-"
_LONG_OBS_REPEAT = 40
LONG_OBSERVATION = _LONG_OBS_UNIT * _LONG_OBS_REPEAT
LONG_OBSERVATION_LENGTH = len(LONG_OBSERVATION)  # 16 * 40 = 640


class ExceptionLifecycle(str, Enum):
    """Lifecycle for the smallest typed exception representation (EXC not in prod)."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class FixtureAsset:
    """Stable asset identity used by canonical results."""

    asset_id: str
    client_id: str
    label: str
    inventory_key: str


@dataclass(frozen=True, slots=True)
class FixtureFramework:
    """Framework carrying its own REQ-001 (not interchangeable across ids)."""

    framework_id: str
    version: str
    title: str
    requirements: tuple[Requirement, ...]


@dataclass(frozen=True, slots=True)
class FixtureException:
    """Typed exception record for fixture tests (production EXC registry absent)."""

    exception_id: UUID
    client_id: str
    asset_id: str
    framework_id: str
    framework_version: str
    requirement_id: str
    lifecycle: ExceptionLifecycle
    reason: str
    created_at: datetime
    valid_from: datetime
    valid_until: datetime | None
    revoked_at: datetime | None = None
    revocation_reason: str = ""


@dataclass(frozen=True, slots=True)
class ModelResponseScenario:
    """Named deterministic LLM response configuration."""

    name: str
    content: str | None = None
    fail_with: BaseException | None = None
    timeout: bool = False


@dataclass(frozen=True, slots=True)
class CanonicalScenario:
    """Immutable canonical dataset; build a fresh instance per test via factory."""

    clock: FixedClock
    clients: tuple[Client, ...]
    audit_runs: tuple[AuditRun, ...]
    assets: tuple[FixtureAsset, ...]
    frameworks: tuple[FixtureFramework, ...]
    requirements: tuple[Requirement, ...]
    results: tuple[Finding, ...]
    exceptions: tuple[FixtureException, ...]
    model_responses: tuple[ModelResponseScenario, ...]
    # Explicit pointers for history / exception assertions
    previous_comparable_result: Finding
    previous_noncomparable_result: Finding
    current_comparable_anchor: Finding
    active_exception: FixtureException
    expired_exception: FixtureException
    revoked_exception: FixtureException
    long_observation: str = LONG_OBSERVATION
    long_observation_length: int = LONG_OBSERVATION_LENGTH
    # Mutable working copies are never stored here; use :meth:`mutable_results`.
    _sentinel: tuple[()] = field(default=(), repr=False)

    def result_by_status(self, status: FindingStatus) -> Finding:
        """Return the dedicated showcase result for ``status``."""
        dedicated = {
            "pass": RESULT_PASS_ID,
            "fail": RESULT_FAIL_ID,
            "partial": RESULT_PARTIAL_ID,
            "error": RESULT_ERROR_ID,
            "not_tested": RESULT_NOT_TESTED_ID,
            "not_applicable": RESULT_NOT_APPLICABLE_ID,
            "accepted_exception": RESULT_ACCEPTED_EXCEPTION_ID,
        }
        target = dedicated.get(status)
        for finding in self.results:
            if target and finding.result_id == target:
                return finding
            if target is None and finding.status == status:
                return finding
        raise KeyError(status)

    def results_by_status(self) -> dict[str, Finding]:
        """Map each required showcase status to its dedicated finding."""
        return {
            "pass": self.result_by_status("pass"),
            "fail": self.result_by_status("fail"),
            "partial": self.result_by_status("partial"),
            "error": self.result_by_status("error"),
            "not_tested": self.result_by_status("not_tested"),
            "not_applicable": self.result_by_status("not_applicable"),
            "accepted_exception": self.result_by_status("accepted_exception"),
        }

    def mutable_results(self) -> dict[str, Finding]:
        """Fresh dict of deep-copied findings for tests that mutate state."""
        return {f.result_id: f.model_copy(deep=True) for f in self.results}

    def build_fake_llm(self, scenario_name: str) -> DeterministicFakeChatModel:
        """Construct a :class:`DeterministicFakeChatModel` for a named response."""
        for item in self.model_responses:
            if item.name == scenario_name:
                if item.timeout:
                    return DeterministicFakeChatModel(timeout=True)
                if item.fail_with is not None:
                    return DeterministicFakeChatModel(fail_with=item.fail_with)
                return DeterministicFakeChatModel(
                    responses=[item.content or ""],
                    default_response=item.content or "",
                )
        raise KeyError(scenario_name)


def exception_is_applicable(
    exception: FixtureException,
    *,
    clock: FixedClock | None = None,
    finding: Finding | None = None,
) -> bool:
    """Evaluate exception applicability against an injected clock (not wall time).

    Production has no exception registry yet (EXC-001); this is the smallest typed
    evaluation used by AUD-003 fixture tests.
    """
    now = (clock or FIXED_CLOCK).now()
    if exception.lifecycle == ExceptionLifecycle.REVOKED:
        return False
    if exception.lifecycle == ExceptionLifecycle.EXPIRED:
        return False
    if exception.valid_from > now:
        return False
    if exception.valid_until is not None and exception.valid_until <= now:
        return False
    if finding is not None:
        if exception.client_id != finding.client_id:
            return False
        if exception.asset_id != finding.asset_id:
            return False
        if exception.framework_id != finding.framework_id:
            return False
        if exception.framework_version != finding.framework_version:
            return False
        if exception.requirement_id != finding.requirement_id:
            return False
    return exception.lifecycle == ExceptionLifecycle.ACTIVE


def select_previous_comparable(
    *,
    current: Finding,
    candidates: Mapping[str, Finding] | list[Finding],
) -> Finding | None:
    """Select a previous result using production historical identity."""
    items = candidates.values() if isinstance(candidates, Mapping) else candidates
    for previous in items:
        if previous.audit_run_id == current.audit_run_id:
            continue
        if is_historically_comparable(previous, current):
            return previous
    return None


def _req(req_id: str, title: str, *, framework_hint: str) -> Requirement:
    return Requirement(
        id=req_id,
        title=title,
        category="Security",
        severity="High",
        how_to_verify=f"Verify {framework_hint} control for {req_id}",
        pass_criteria=f"{req_id} meets {framework_hint} baseline",
    )


def _finding(
    *,
    result_id: str,
    client_id: str,
    audit_run_id: str,
    asset_id: str,
    framework_id: str,
    requirement_id: str,
    status: FindingStatus,
    evidence: str,
    remediation: str = "",
    notes: str = "",
    title: str = "",
) -> Finding:
    return Finding(
        result_id=result_id,
        client_id=client_id,
        audit_run_id=audit_run_id,
        asset_id=asset_id,
        framework_id=framework_id,
        framework_version=FRAMEWORK_VERSION,
        requirement_id=requirement_id,
        status=status,
        title=title or requirement_id,
        severity="High",
        category="Security",
        evidence=evidence,
        remediation=remediation,
        notes=notes,
        pass_criteria="Deterministic fixture pass criteria",
    )


def build_canonical_scenario() -> CanonicalScenario:
    """Return a fresh immutable canonical scenario (safe to call per test)."""
    clients = (
        Client(
            client_id=CLIENT_ALPHA_ID,
            display_name="Client Alpha",
            slug="client_alpha",
            created_at=TS_ALPHA_PREVIOUS.isoformat(),
            updated_at=TS_ALPHA_CURRENT.isoformat(),
        ),
        Client(
            client_id=CLIENT_BETA_ID,
            display_name="Client Beta",
            slug="client_beta",
            created_at=TS_BETA_CURRENT.isoformat(),
            updated_at=TS_BETA_CURRENT.isoformat(),
        ),
    )
    audit_runs = (
        AuditRun(
            audit_run_id=RUN_ALPHA_PREVIOUS_ID,
            client_id=CLIENT_ALPHA_ID,
            status=AuditRunStatus.COMPLETED,
            created_at=TS_ALPHA_PREVIOUS,
            started_at=TS_ALPHA_PREVIOUS,
            finished_at=TS_ALPHA_PREVIOUS + timedelta(hours=2),
            evidence_run_id=f"client_alpha/{RUN_ALPHA_PREVIOUS_ID}",
        ),
        AuditRun(
            audit_run_id=RUN_ALPHA_CURRENT_ID,
            client_id=CLIENT_ALPHA_ID,
            status=AuditRunStatus.RUNNING,
            created_at=TS_ALPHA_CURRENT,
            started_at=TS_ALPHA_CURRENT,
            evidence_run_id=f"client_alpha/{RUN_ALPHA_CURRENT_ID}",
        ),
        AuditRun(
            audit_run_id=RUN_BETA_CURRENT_ID,
            client_id=CLIENT_BETA_ID,
            status=AuditRunStatus.RUNNING,
            created_at=TS_BETA_CURRENT,
            started_at=TS_BETA_CURRENT,
            evidence_run_id=f"client_beta/{RUN_BETA_CURRENT_ID}",
        ),
    )
    assets = (
        FixtureAsset(
            asset_id=ASSET_LINUX_01_ID,
            client_id=CLIENT_ALPHA_ID,
            label="asset_linux_01",
            inventory_key="linux-01",
        ),
        FixtureAsset(
            asset_id=ASSET_LINUX_02_ID,
            client_id=CLIENT_ALPHA_ID,
            label="asset_linux_02",
            inventory_key="linux-02",
        ),
        FixtureAsset(
            asset_id=ASSET_BETA_01_ID,
            client_id=CLIENT_BETA_ID,
            label="asset_beta_01",
            inventory_key="beta-01",
        ),
    )
    linux_req = _req("REQ-001", "SSH root login disabled", framework_hint="linux")
    pg_req = _req("REQ-001", "PostgreSQL scram auth", framework_hint="postgresql")
    frameworks = (
        FixtureFramework(
            framework_id=FRAMEWORK_LINUX_ID,
            version=FRAMEWORK_VERSION,
            title="Linux host hardening",
            requirements=(linux_req,),
        ),
        FixtureFramework(
            framework_id=FRAMEWORK_POSTGRESQL_ID,
            version=FRAMEWORK_VERSION,
            title="PostgreSQL CIS",
            requirements=(pg_req,),
        ),
    )

    active = FixtureException(
        exception_id=EXCEPTION_ACTIVE_ID,
        client_id=CLIENT_ALPHA_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        framework_version=FRAMEWORK_VERSION,
        requirement_id="REQ-001",
        lifecycle=ExceptionLifecycle.ACTIVE,
        reason="Temporary compensating control approved for Q3",
        created_at=datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_from=datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_until=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
    )
    expired = FixtureException(
        exception_id=EXCEPTION_EXPIRED_ID,
        client_id=CLIENT_ALPHA_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        framework_version=FRAMEWORK_VERSION,
        requirement_id="REQ-001",
        lifecycle=ExceptionLifecycle.EXPIRED,
        reason="Expired waiver — do not accept",
        created_at=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_from=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_until=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    revoked = FixtureException(
        exception_id=EXCEPTION_REVOKED_ID,
        client_id=CLIENT_ALPHA_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        framework_version=FRAMEWORK_VERSION,
        requirement_id="REQ-001",
        lifecycle=ExceptionLifecycle.REVOKED,
        reason="Revoked after control regression",
        created_at=datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_from=datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_until=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        revoked_at=datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
        revocation_reason="Control owner withdrew approval",
    )

    # Showcase statuses on current alpha run / linux-01 / framework_linux / REQ-001
    # (except fail/partial/error/not_* which use linux-02 or postgresql to keep
    # logical keys unique under CORE-003).
    result_pass = _finding(
        result_id=RESULT_PASS_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_02_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-001",
        status="pass",
        evidence="PermitRootLogin no",
        remediation="",
    )
    result_fail = _finding(
        result_id=RESULT_FAIL_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_02_ID,
        framework_id=FRAMEWORK_POSTGRESQL_ID,
        requirement_id="REQ-001",
        status="fail",
        evidence="password_encryption=md5",
        remediation="Set scram-sha-256",
    )
    result_partial = _finding(
        result_id=RESULT_PARTIAL_ID,
        client_id=CLIENT_BETA_ID,
        audit_run_id=RUN_BETA_CURRENT_ID,
        asset_id=ASSET_BETA_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-001",
        status="partial",
        evidence="Partial hardening observed",
        remediation="Complete remaining controls",
    )
    result_error = _finding(
        result_id=RESULT_ERROR_ID,
        client_id=CLIENT_BETA_ID,
        audit_run_id=RUN_BETA_CURRENT_ID,
        asset_id=ASSET_BETA_01_ID,
        framework_id=FRAMEWORK_POSTGRESQL_ID,
        requirement_id="REQ-001",
        status="error",
        evidence="SSH error: connection refused",
        remediation="Check connectivity",
    )
    result_not_tested = _finding(
        result_id=RESULT_NOT_TESTED_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_02_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-002",
        status="not_tested",
        evidence="Not executed in this run",
        title="REQ-002",
    )
    result_not_applicable = _finding(
        result_id=RESULT_NOT_APPLICABLE_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_02_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-003",
        status="not_applicable",
        evidence="Control not applicable to container host",
        title="REQ-003",
    )
    result_accepted = _finding(
        result_id=RESULT_ACCEPTED_EXCEPTION_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-001",
        status="accepted_exception",
        evidence="Root login still enabled; covered by active exception",
        remediation="Track compensating control",
        notes=f"exception_id={EXCEPTION_ACTIVE_ID}",
    )

    # History: previous comparable = same client/asset/fw/REQ as accepted_exception
    # anchor on previous run; non-comparable = same REQ-001 but postgresql framework.
    previous_comparable = _finding(
        result_id=RESULT_PREVIOUS_COMPARABLE_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-001",
        status="fail",
        evidence="Previous run: PermitRootLogin yes",
        remediation="Disable root login",
    )
    previous_noncomparable = _finding(
        result_id=RESULT_PREVIOUS_NONCOMPARABLE_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_PREVIOUS_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_POSTGRESQL_ID,
        requirement_id="REQ-001",
        status="pass",
        evidence="Previous PG scram OK — different framework than linux REQ-001",
    )
    current_anchor = result_accepted

    formula_eq = _finding(
        result_id=RESULT_FORMULA_EQ_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-010",
        status="fail",
        evidence="=CMD('calc')",
        title="REQ-010",
    )
    formula_plus = _finding(
        result_id=RESULT_FORMULA_PLUS_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-011",
        status="fail",
        evidence="+1234+5678",
        title="REQ-011",
    )
    formula_minus = _finding(
        result_id=RESULT_FORMULA_MINUS_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-012",
        status="fail",
        evidence="-SUM(A1:A9)",
        title="REQ-012",
    )
    formula_at = _finding(
        result_id=RESULT_FORMULA_AT_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-013",
        status="fail",
        evidence="@SUM(A1:A9)",
        title="REQ-013",
    )
    ru_obs = _finding(
        result_id=RESULT_RU_OBS_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-014",
        status="fail",
        evidence="Обнаружен вход root по SSH на хосте",
        remediation="Отключить PermitRootLogin",
        title="REQ-014",
    )
    en_obs = _finding(
        result_id=RESULT_EN_OBS_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-015",
        status="pass",
        evidence="SSH root login is disabled on the host",
        title="REQ-015",
    )
    long_obs = _finding(
        result_id=RESULT_LONG_OBS_ID,
        client_id=CLIENT_ALPHA_ID,
        audit_run_id=RUN_ALPHA_CURRENT_ID,
        asset_id=ASSET_LINUX_01_ID,
        framework_id=FRAMEWORK_LINUX_ID,
        requirement_id="REQ-016",
        status="partial",
        evidence=LONG_OBSERVATION,
        title="REQ-016",
    )

    results = (
        result_pass,
        result_fail,
        result_partial,
        result_error,
        result_not_tested,
        result_not_applicable,
        result_accepted,
        previous_comparable,
        previous_noncomparable,
        formula_eq,
        formula_plus,
        formula_minus,
        formula_at,
        ru_obs,
        en_obs,
        long_obs,
    )

    model_responses = (
        ModelResponseScenario(
            name="valid_structured_en",
            content=(
                '{"status":"fail","observation":"SSH root login enabled",'
                '"recommendation":"Set PermitRootLogin no"}'
            ),
        ),
        ModelResponseScenario(
            name="valid_structured_ru",
            content=(
                '{"status":"fail","observation":"Включён вход root по SSH",'
                '"recommendation":"Установить PermitRootLogin no"}'
            ),
        ),
        ModelResponseScenario(
            name="malformed",
            content="NOT_JSON{{{broken",
        ),
        ModelResponseScenario(
            name="provider_failure",
            fail_with=RuntimeError("provider_unavailable"),
        ),
        ModelResponseScenario(
            name="timeout",
            timeout=True,
        ),
    )

    # Freeze tuples so callers cannot mutate shared structure in place.
    scenario = CanonicalScenario(
        clock=FIXED_CLOCK,
        clients=clients,
        audit_runs=audit_runs,
        assets=assets,
        frameworks=frameworks,
        requirements=(linux_req, pg_req),
        results=results,
        exceptions=(active, expired, revoked),
        model_responses=model_responses,
        previous_comparable_result=previous_comparable,
        previous_noncomparable_result=previous_noncomparable,
        current_comparable_anchor=current_anchor,
        active_exception=active,
        expired_exception=expired,
        revoked_exception=revoked,
    )
    # Defensive: return a deepcopy so module-level accidental retention cannot share.
    return deepcopy(scenario)


# Re-export helpers used by validation tests
__all__ = [
    "FIXED_NOW",
    "FIXED_CLOCK",
    "LONG_OBSERVATION",
    "LONG_OBSERVATION_LENGTH",
    "CanonicalScenario",
    "ExceptionLifecycle",
    "FixtureException",
    "build_canonical_scenario",
    "exception_is_applicable",
    "select_previous_comparable",
    "historical_comparison_key",
    "is_historically_comparable",
]

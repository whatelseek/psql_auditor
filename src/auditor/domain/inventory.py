"""Validated, versioned client inventory model (INPUT-003).

Normalized representation of client infrastructure declared in inventory files.
Facts carry provenance so inventory-declared, discovered, inferred, and
user-confirmed data remain distinguishable.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictStr,
    field_validator,
    model_validator,
)

FactSource = Literal[
    "inventory",
    "discovered",
    "user_confirmed",
    "inferred",
    "questionnaire",
    "previous_audit",
    "unknown",
]
FactConfidence = StrictFloat
DetectionStatus = Literal[
    "confirmed",
    "probable",
    "possible",
    "not_detected",
    "unknown",
]
ValidationLevel = Literal["error", "warning", "information"]
ConnectionType = Literal["ssh", "winrm", "postgresql", "mysql", "oracle", "unknown"]

CLIENT_NAME_PATTERN = r"^[A-Za-z0-9_]+$"
SUPPORTED_INVENTORY_FORMATS = frozenset({"markdown", "yaml", "json"})


class InventoryFact(BaseModel):
    """One provenance-bearing fact about a host, service, or client."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host_id: StrictStr | None = None
    fact: StrictStr = Field(min_length=1)
    value: Any
    source: FactSource
    confidence: StrictFloat = 1.0
    evidence_ref: StrictStr | None = None

    @field_validator("confidence")
    @classmethod
    def _confidence(cls, value: float) -> float:
        if value < 0.0 or value > 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        return value


class CredentialReference(BaseModel):
    """Secret-free credential pointer (never stores plaintext secrets)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    access: ConnectionType
    host: StrictStr = Field(min_length=1)
    port: int | None = None
    username: StrictStr = ""
    secret_ref: StrictStr = ""
    database: StrictStr = ""
    target_host_id: StrictStr | None = None
    has_secret: StrictBool = False


class InventoryService(BaseModel):
    """Declared or detected service on a host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1)
    port: int | None = None
    role: StrictStr = ""
    status: DetectionStatus = "confirmed"
    source: FactSource = "inventory"
    confidence: StrictFloat = 1.0


class InventoryHost(BaseModel):
    """One normalized host asset from client inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host_id: StrictStr = Field(min_length=1)
    hostname: StrictStr = ""
    address: StrictStr = ""
    os_family: StrictStr = ""
    os_name: StrictStr = ""
    roles: tuple[StrictStr, ...] = ()
    services: tuple[InventoryService, ...] = ()
    connection_types: tuple[ConnectionType, ...] = ()
    credential_refs: tuple[StrictStr, ...] = ()
    notes: StrictStr = ""
    facts: tuple[InventoryFact, ...] = ()

    @field_validator("host_id")
    @classmethod
    def _host_id(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("host_id must be non-empty")
        return text


class ValidationIssue(BaseModel):
    """Inventory validation finding classified by severity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    level: ValidationLevel
    code: StrictStr = Field(min_length=1)
    message: StrictStr = Field(min_length=1)
    host_id: StrictStr | None = None
    location: StrictStr = ""


class InventoryVersion(BaseModel):
    """Immutable inventory snapshot identity for audit reproducibility."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version_id: StrictStr = Field(min_length=1)
    content_hash: StrictStr = Field(min_length=1)
    source_format: StrictStr = Field(min_length=1)
    source_path: StrictStr = ""
    recorded_at: StrictStr = Field(min_length=1)


class ClientInventory(BaseModel):
    """Normalized client inventory document (INPUT-003)."""

    # Not strict: JSON persistence round-trips lists into tuple fields.
    model_config = ConfigDict(extra="forbid", frozen=True)

    client_id: StrictStr = Field(min_length=1)
    hosts: tuple[InventoryHost, ...] = ()
    databases: tuple[StrictStr, ...] = ()
    applications: tuple[StrictStr, ...] = ()
    network_devices: tuple[StrictStr, ...] = ()
    credentials: tuple[CredentialReference, ...] = ()
    questionnaires: tuple[StrictStr, ...] = ()
    exceptions: tuple[StrictStr, ...] = ()
    facts: tuple[InventoryFact, ...] = ()
    version: InventoryVersion
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.level == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.level == "warning")

    def hosts_without_errors(self) -> list[InventoryHost]:
        blocked = {i.host_id for i in self.issues if i.level == "error" and i.host_id}
        return [h for h in self.hosts if h.host_id not in blocked]

    @model_validator(mode="after")
    def _unique_hosts(self) -> ClientInventory:
        seen: set[str] = set()
        for host in self.hosts:
            key = host.host_id.lower()
            if key in seen:
                raise ValueError(f"duplicate host_id {host.host_id!r}")
            seen.add(key)
        return self


class TechnologyDetection(BaseModel):
    """Technology detection result with confidence and status."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technology_id: StrictStr = Field(min_length=1)
    target_id: StrictStr = Field(min_length=1)
    status: DetectionStatus
    confidence: StrictFloat
    evidence: tuple[StrictStr, ...] = ()
    source: FactSource = "inventory"


class FrameworkSelectionDecision(BaseModel):
    """Why a framework was selected or rejected for a target."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework_id: StrictStr = Field(min_length=1)
    framework_version: StrictStr = ""
    target_id: StrictStr = Field(min_length=1)
    reason: StrictStr = Field(min_length=1)
    status: Literal["selected", "rejected", "considered"]

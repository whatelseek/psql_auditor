"""Host capability snapshot collected during tool-driven discovery (INPUT-005)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class SnapshotOsInfo:
    """OS identity within a host capability snapshot."""

    family: str = ""
    distribution: str = ""
    version: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "family": self.family,
            "distribution": self.distribution,
            "version": self.version,
        }


@dataclass(slots=True)
class SnapshotAccessMethod:
    """One transport access outcome (e.g. SSH)."""

    available: bool = False
    status: str = "unavailable"

    def to_dict(self) -> dict[str, Any]:
        return {"available": self.available, "status": self.status}


@dataclass(slots=True)
class SnapshotTechnology:
    """Technology detection row embedded in a capability snapshot."""

    technology_id: str
    status: str
    version: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technology_id": self.technology_id,
            "status": self.status,
            "version": self.version,
            "evidence": list(self.evidence),
        }


@dataclass(slots=True)
class HostCapabilitySnapshot:
    """Normalized per-host capability facts used for framework selection.

    Persisted as ``host_capability_snapshot.v1`` (secret-free).
    """

    schema: str = "host_capability_snapshot.v1"
    client_id: str = ""
    host_id: str = ""
    inventory_version_id: str = ""
    asset_type: str = "server"
    platform: str = ""
    os: SnapshotOsInfo = field(default_factory=SnapshotOsInfo)
    access: dict[str, SnapshotAccessMethod] = field(default_factory=dict)
    technologies: list[SnapshotTechnology] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    running_services: list[str] = field(default_factory=list)
    tool_catalog_hash: str = ""
    capability_policy_hash: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    tool_ids: tuple[str, ...] = ()
    collector: str = "ssh"
    confidence: str = "high"
    collected_at: str = ""
    limitations: list[str] = field(default_factory=list)
    error: str = ""
    error_code: str = ""
    # Legacy flat aliases retained for reconcile helpers / tests.
    os_name: str = ""
    os_family: str = ""
    os_version: str = ""
    ssh_access: bool = False
    postgresql_present: bool = False
    postgresql_version: str = ""
    evidence_ref: str = ""
    transport: str = "ssh"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the v1 document shape (credentials never included)."""
        access = {name: method.to_dict() for name, method in self.access.items()}
        return {
            "schema": self.schema or "host_capability_snapshot.v1",
            "client_id": self.client_id,
            "host_id": self.host_id,
            "inventory_version_id": self.inventory_version_id,
            "asset_type": self.asset_type or "server",
            "platform": self.platform or self.os.family or self.os_family,
            "os": self.os.to_dict(),
            "access": access,
            "technologies": [t.to_dict() for t in self.technologies],
            "listening_ports": list(self.listening_ports),
            "running_services": list(self.running_services),
            "tool_catalog_hash": self.tool_catalog_hash,
            "capability_policy_hash": self.capability_policy_hash,
            "evidence_refs": list(self.evidence_refs),
            "tool_ids": list(self.tool_ids),
            "collector": self.collector,
            "confidence": self.confidence,
            "collected_at": self.collected_at,
            "limitations": list(self.limitations),
            "error": self.error,
            "error_code": self.error_code,
        }

    def legacy_dict(self) -> dict[str, Any]:
        """Flat dict used by older callers (includes compatibility aliases)."""
        data = asdict(self)
        data["os"] = self.os.to_dict()
        data["access"] = {k: v.to_dict() for k, v in self.access.items()}
        data["technologies"] = [t.to_dict() for t in self.technologies]
        data["tool_ids"] = list(self.tool_ids)
        data["listening_ports"] = list(self.listening_ports)
        data["running_services"] = list(self.running_services)
        data["evidence_refs"] = list(self.evidence_refs)
        data["limitations"] = list(self.limitations)
        return data

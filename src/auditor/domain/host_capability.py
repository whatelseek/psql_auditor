"""Host capability snapshot collected during tool-driven discovery (INPUT-005)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class HostCapabilitySnapshot:
    """Normalized per-host capability facts used for framework selection.

    Captures OS identity, SSH reachability, running services, listening ports,
    and PostgreSQL presence/version from registry-authorized discovery tools.
    """

    host_id: str
    os_name: str = ""
    os_family: str = ""
    os_version: str = ""
    ssh_access: bool = False
    running_services: list[str] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    postgresql_present: bool = False
    postgresql_version: str = ""
    transport: str = "ssh"
    tool_ids: tuple[str, ...] = ()
    collector: str = "ssh"
    confidence: str = "high"
    evidence_ref: str = ""
    collected_at: str = ""
    limitations: list[str] = field(default_factory=list)
    error: str = ""
    error_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tool_ids"] = list(self.tool_ids)
        data["running_services"] = list(self.running_services)
        data["listening_ports"] = list(self.listening_ports)
        data["limitations"] = list(self.limitations)
        return data

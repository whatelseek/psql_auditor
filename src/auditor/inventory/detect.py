"""Technology detection from inventory-declared evidence."""

from __future__ import annotations

from auditor.domain.inventory import (
    ClientInventory,
    DetectionStatus,
    TechnologyDetection,
)

# Weak signals alone must not confirm a technology (spec §5.4).
_PORT_ONLY_CONFIDENCE = 0.4


def detect_technologies(inventory: ClientInventory) -> list[TechnologyDetection]:
    """Detect technologies from inventory fields and declared services/ports.

    Inventory-declared services are treated as confirmed. Port-only evidence
    without a matching service name yields ``possible``, not ``confirmed``.
    """
    detections: list[TechnologyDetection] = []
    for host in inventory.hosts_without_errors():
        service_names = {s.name for s in host.services}
        ports = {s.port for s in host.services if s.port is not None}

        if host.os_family == "linux" or "ubuntu" in (host.os_name or "").lower():
            tech = "ubuntu" if "ubuntu" in (host.os_name or "").lower() else "linux"
            detections.append(
                TechnologyDetection(
                    technology_id=tech,
                    target_id=host.host_id,
                    status="confirmed",
                    confidence=1.0,
                    evidence=(f"os={host.os_name or host.os_family}",),
                    source="inventory",
                )
            )
        elif host.os_family == "windows":
            detections.append(
                TechnologyDetection(
                    technology_id="windows_server",
                    target_id=host.host_id,
                    status="confirmed",
                    confidence=1.0,
                    evidence=(f"os={host.os_name or host.os_family}",),
                    source="inventory",
                )
            )

        if "postgresql" in service_names:
            detections.append(
                TechnologyDetection(
                    technology_id="postgresql",
                    target_id=f"{host.host_id}/postgresql",
                    status="confirmed",
                    confidence=1.0,
                    evidence=("service=postgresql",),
                    source="inventory",
                )
            )
        elif 5432 in ports:
            detections.append(
                TechnologyDetection(
                    technology_id="postgresql",
                    target_id=f"{host.host_id}/postgresql",
                    status="possible",
                    confidence=_PORT_ONLY_CONFIDENCE,
                    evidence=("port=5432",),
                    source="inventory",
                )
            )

        if "ssh" in service_names or "ssh" in host.connection_types:
            detections.append(
                TechnologyDetection(
                    technology_id="ssh",
                    target_id=host.host_id,
                    status="confirmed",
                    confidence=1.0,
                    evidence=("connection=ssh",),
                    source="inventory",
                )
            )
        if "winrm" in service_names or "winrm" in host.connection_types:
            detections.append(
                TechnologyDetection(
                    technology_id="winrm",
                    target_id=host.host_id,
                    status="confirmed",
                    confidence=1.0,
                    evidence=("connection=winrm",),
                    source="inventory",
                )
            )
        for name in ("nginx", "redis", "mysql"):
            if name in service_names:
                detections.append(
                    TechnologyDetection(
                        technology_id=name,
                        target_id=f"{host.host_id}/{name}",
                        status="confirmed",
                        confidence=1.0,
                        evidence=(f"service={name}",),
                        source="inventory",
                    )
                )

    return detections


def detection_status_for(
    detections: list[TechnologyDetection],
    technology_id: str,
    target_prefix: str,
) -> DetectionStatus:
    """Return best detection status for technology on a target prefix."""
    rank = {
        "confirmed": 4,
        "probable": 3,
        "possible": 2,
        "unknown": 1,
        "not_detected": 0,
    }
    best: DetectionStatus = "not_detected"
    for det in detections:
        if det.technology_id != technology_id:
            continue
        if not det.target_id.startswith(target_prefix):
            continue
        if rank[det.status] > rank[best]:
            best = det.status
    return best

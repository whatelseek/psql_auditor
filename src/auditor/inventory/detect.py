"""Technology detection from inventory-declared and discovered evidence."""

from __future__ import annotations

from auditor.domain.inventory import (
    ClientInventory,
    DetectionStatus,
    TechnologyDetection,
)

# Weak signals alone must not confirm a technology (spec §5.4).
_PORT_ONLY_CONFIDENCE = 0.4


def detect_technologies(inventory: ClientInventory) -> list[TechnologyDetection]:
    """Detect technologies from reconciled inventory + discovery facts.

    Confirmed inventory or discovered services → ``confirmed``.
    Port-only evidence without a matching service name → ``possible``.
    Conflicting OS evidence → ``unknown`` for OS technologies.
    """
    conflicted_os = {c.host_id for c in inventory.conflicts if c.fact in {"os_family", "os_name"}}
    detections: list[TechnologyDetection] = []
    for host in inventory.hosts_without_errors():
        service_names = {s.name for s in host.services}
        confirmed_services = {
            s.name for s in host.services if s.status == "confirmed" and s.confidence >= 1.0
        }
        ports = {
            int(f.value)
            for f in host.facts
            if f.fact == "listening_port" and isinstance(f.value, int)
        }
        ports |= {s.port for s in host.services if s.port is not None}

        if host.host_id in conflicted_os:
            detections.append(
                TechnologyDetection(
                    technology_id="os",
                    target_id=host.host_id,
                    status="unknown",
                    confidence=0.0,
                    evidence=("fact_conflict:os_family",),
                    source="unknown",
                )
            )
        elif host.os_family == "linux" or "ubuntu" in (host.os_name or "").lower():
            tech = "ubuntu" if "ubuntu" in (host.os_name or "").lower() else "linux"
            os_fact = next((f for f in host.facts if f.fact == "os_family"), None)
            source = os_fact.source if os_fact else "inventory"
            detections.append(
                TechnologyDetection(
                    technology_id=tech,
                    target_id=host.host_id,
                    status="confirmed",
                    confidence=1.0,
                    evidence=(f"os={host.os_name or host.os_family}",),
                    source=source,
                )
            )
        elif host.os_family == "windows":
            os_fact = next((f for f in host.facts if f.fact == "os_family"), None)
            source = os_fact.source if os_fact else "inventory"
            detections.append(
                TechnologyDetection(
                    technology_id="windows_server",
                    target_id=host.host_id,
                    status="confirmed",
                    confidence=1.0,
                    evidence=(f"os={host.os_name or host.os_family}",),
                    source=source,
                )
            )

        if "postgresql" in confirmed_services or "postgresql" in service_names:
            svc = next(s for s in host.services if s.name == "postgresql")
            detections.append(
                TechnologyDetection(
                    technology_id="postgresql",
                    target_id=f"{host.host_id}/postgresql",
                    status="confirmed" if svc.confidence >= 1.0 else "probable",
                    confidence=float(svc.confidence),
                    evidence=(f"service=postgresql source={svc.source}",),
                    source=svc.source,
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
                    source="discovered",
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

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

    Status vocabulary (INPUT-005):

    * ``confirmed`` — strong evidence (binary + service, or confirmed service)
    * ``suspected`` — weak signal only (e.g. port 5432 alone)
    * ``absent`` — discovery succeeded with no evidence of the technology
    * ``unknown`` — discovery failed / conflicting evidence
    * ``unsupported`` — asset type has no registered adapter/capability
    """
    conflicted_os = {c.host_id for c in inventory.conflicts if c.fact in {"os_family", "os_name"}}
    discovery_failed = {
        i.host_id
        for i in inventory.issues
        if i.host_id
        and i.code
        in {
            "discovery_failed",
            "connection_timeout",
            "authentication_failed",
            "host_unreachable",
            "command_timeout",
            "partial_discovery",
        }
        and i.level in {"error", "warning"}
    }
    detections: list[TechnologyDetection] = []
    for host in inventory.hosts_without_errors():
        if host.is_unsupported_network_device:
            missing = ["cisco.cli.read"] if (host.vendor or "").lower() in {"", "cisco"} else []
            if (host.vendor or "").lower() and (host.vendor or "").lower() != "cisco":
                missing = [f"{host.vendor.lower()}.cli.read"]
            detections.append(
                TechnologyDetection(
                    technology_id="network_device",
                    target_id=host.host_id,
                    status="unsupported",
                    confidence=1.0,
                    evidence=(
                        f"asset_type={host.asset_type or 'network_device'}",
                        f"vendor={host.vendor or 'unknown'}",
                        *(f"missing={cap}" for cap in missing),
                    ),
                    source="inventory",
                )
            )
            continue

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
        elif host.host_id in discovery_failed and not host.os_family:
            detections.append(
                TechnologyDetection(
                    technology_id="os",
                    target_id=host.host_id,
                    status="unknown",
                    confidence=0.0,
                    evidence=("discovery_failed",),
                    source="discovered",
                )
            )

        if "postgresql" in confirmed_services or "postgresql" in service_names:
            svc = next(s for s in host.services if s.name == "postgresql")
            # Strong evidence only → confirmed; weaker inventory/discovery → suspected.
            if svc.confidence >= 1.0 and svc.status in {"confirmed", "probable"}:
                pg_status: DetectionStatus = "confirmed"
            elif svc.confidence >= 0.7:
                pg_status = "confirmed"
            else:
                pg_status = "suspected"
            detections.append(
                TechnologyDetection(
                    technology_id="postgresql",
                    target_id=f"{host.host_id}/postgresql",
                    status=pg_status,
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
                    status="suspected",
                    confidence=_PORT_ONLY_CONFIDENCE,
                    evidence=("port=5432",),
                    source="discovered",
                )
            )
        elif host.os_family in {"linux", "windows"} and host.host_id not in discovery_failed:
            # Explicit absent when discovery produced OS facts but no PG signals.
            detections.append(
                TechnologyDetection(
                    technology_id="postgresql",
                    target_id=f"{host.host_id}/postgresql",
                    status="absent",
                    confidence=1.0,
                    evidence=("no_postgresql_binary_service_or_port",),
                    source="discovered",
                )
            )
        elif host.host_id in discovery_failed:
            detections.append(
                TechnologyDetection(
                    technology_id="postgresql",
                    target_id=f"{host.host_id}/postgresql",
                    status="unknown",
                    confidence=0.0,
                    evidence=("discovery_failed",),
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
        "confirmed": 5,
        "suspected": 4,
        "probable": 4,
        "possible": 3,
        "unknown": 2,
        "unsupported": 2,
        "absent": 1,
        "not_detected": 0,
    }
    best: DetectionStatus = "absent"
    found = False
    for det in detections:
        if det.technology_id != technology_id:
            continue
        if not det.target_id.startswith(target_prefix):
            continue
        found = True
        if rank.get(det.status, 0) > rank.get(best, 0):
            best = det.status
    return best if found else "absent"

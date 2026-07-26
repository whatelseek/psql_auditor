"""Automatic framework selection from inventory technology detections."""

from __future__ import annotations

from pathlib import Path

from auditor.domain.inventory import (
    ClientInventory,
    FrameworkSelectionDecision,
    TechnologyDetection,
)
from auditor.frameworks import Framework, get_framework, list_frameworks
from auditor.inventory.detect import detection_status_for

# Maps detected technology → preferred framework family / id prefixes.
_TECH_FRAMEWORK_PREFERENCES: dict[str, tuple[str, ...]] = {
    "ubuntu": ("ubuntu_cis_24_l2", "ubuntu"),
    "linux": ("ubuntu_cis_24_l2", "linux"),
    "postgresql": ("postgres_cis", "postgresql"),
    "windows_server": ("windows_server", "windows_cis", "windows"),
    "infrastructure": ("host_facts", "it_audit"),
}


def _framework_version(fw: Framework | None) -> str:
    return (fw.version if fw and fw.version else "") or "0"


def select_frameworks_for_inventory(
    inventory: ClientInventory,
    detections: list[TechnologyDetection],
    *,
    agents_dir: Path | str | None = None,
) -> list[FrameworkSelectionDecision]:
    """Select audit frameworks for each host/service based on detections.

    Also records rejected/considered decisions when a technology is only
    weakly evidenced (e.g. port-only PostgreSQL).
    """
    available = {fw.id: fw for fw in list_frameworks(agents_dir)}
    decisions: list[FrameworkSelectionDecision] = []

    # General infrastructure once per client.
    infra_fw = (
        get_framework("host_facts", agents_dir)
        or get_framework("it_audit", agents_dir)
        or next((fw for fw in available.values() if fw.domain == "it"), None)
    )
    if infra_fw is not None:
        decisions.append(
            FrameworkSelectionDecision(
                framework_id=infra_fw.id,
                framework_version=_framework_version(infra_fw),
                target_id=f"client:{inventory.client_id}",
                reason="General infrastructure assessment for the client engagement",
                status="selected",
            )
        )
    else:
        decisions.append(
            FrameworkSelectionDecision(
                framework_id="host_facts",
                framework_version="",
                target_id=f"client:{inventory.client_id}",
                reason="No IT/infrastructure framework available in agents directory",
                status="rejected",
            )
        )

    for host in inventory.hosts_without_errors():
        # OS frameworks
        if host.os_family == "linux" or "ubuntu" in (host.os_name or "").lower():
            fw = _pick_available(available, _TECH_FRAMEWORK_PREFERENCES["ubuntu"])
            if fw is not None:
                decisions.append(
                    FrameworkSelectionDecision(
                        framework_id=fw.id,
                        framework_version=_framework_version(fw),
                        target_id=host.host_id,
                        reason=(
                            f"Linux/Ubuntu host confirmed from inventory "
                            f"(os={host.os_name or host.os_family})"
                        ),
                        status="selected",
                    )
                )
            else:
                decisions.append(
                    FrameworkSelectionDecision(
                        framework_id="ubuntu_cis_24_l2",
                        framework_version="",
                        target_id=host.host_id,
                        reason="Ubuntu/Linux detected but no matching framework is installed",
                        status="rejected",
                    )
                )
        elif host.os_family == "windows":
            fw = _pick_available(available, _TECH_FRAMEWORK_PREFERENCES["windows_server"])
            if fw is not None:
                decisions.append(
                    FrameworkSelectionDecision(
                        framework_id=fw.id,
                        framework_version=_framework_version(fw),
                        target_id=host.host_id,
                        reason=(
                            f"Windows Server host confirmed from inventory "
                            f"(os={host.os_name or host.os_family})"
                        ),
                        status="selected",
                    )
                )
            else:
                decisions.append(
                    FrameworkSelectionDecision(
                        framework_id="windows_server",
                        framework_version="",
                        target_id=host.host_id,
                        reason="Windows Server detected but no matching framework is installed",
                        status="rejected",
                    )
                )

        # PostgreSQL
        pg_status = detection_status_for(detections, "postgresql", host.host_id)
        pg_target = f"{host.host_id}/postgresql"
        fw = _pick_available(available, _TECH_FRAMEWORK_PREFERENCES["postgresql"])
        if pg_status == "confirmed" and fw is not None:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id=fw.id,
                    framework_version=_framework_version(fw),
                    target_id=pg_target,
                    reason=("PostgreSQL service confirmed from inventory and connection data"),
                    status="selected",
                )
            )
        elif pg_status in {"possible", "probable"}:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id=fw.id if fw else "postgres_cis",
                    framework_version=_framework_version(fw),
                    target_id=pg_target,
                    reason=(
                        f"PostgreSQL evidence is {pg_status} (weak signal only); "
                        "framework not selected until confirmed"
                    ),
                    status="rejected",
                )
            )
        elif any(s.name == "postgresql" for s in host.services) and fw is None:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id="postgres_cis",
                    framework_version="",
                    target_id=pg_target,
                    reason="PostgreSQL confirmed but postgres framework is unavailable",
                    status="rejected",
                )
            )

    return decisions


def _pick_available(
    available: dict[str, Framework],
    preferences: tuple[str, ...],
) -> Framework | None:
    for pref in preferences:
        if pref in available:
            return available[pref]
        for fw_id, fw in available.items():
            if fw_id.startswith(pref) or pref in fw.aliases:
                return fw
    return None

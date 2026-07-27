"""Automatic framework selection from inventory technology detections.

Default path: declarative Markdown applicability metadata (INPUT-005 dynamic).
Legacy hardcoded platform maps remain available only via
``use_legacy_tech_mapping=True``.
"""

from __future__ import annotations

from pathlib import Path

from auditor.domain.inventory import (
    ClientInventory,
    FrameworkSelectionDecision,
    TechnologyDetection,
)
from auditor.frameworks import Framework, get_framework, list_frameworks
from auditor.inventory.detect import detection_status_for

# Deprecated: kept only for ``use_legacy_tech_mapping=True``.
_TECH_FRAMEWORK_PREFERENCES: dict[str, tuple[str, ...]] = {
    "ubuntu": ("ubuntu_cis_24_l2", "ubuntu", "linux_os", "linux"),
    "linux": ("ubuntu_cis_24_l2", "linux_os", "linux"),
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
    use_legacy_tech_mapping: bool = False,
) -> list[FrameworkSelectionDecision]:
    """Select audit frameworks for each host/service based on detections.

    By default uses declarative Markdown applicability metadata. Pass
    ``use_legacy_tech_mapping=True`` to force the deprecated hardcoded map.
    """
    if use_legacy_tech_mapping:
        return _legacy_select_frameworks_for_inventory(inventory, detections, agents_dir=agents_dir)
    from auditor.inventory.dynamic_select import select_frameworks_dynamic

    return select_frameworks_dynamic(inventory, detections, agents_dir=agents_dir)


def _legacy_select_frameworks_for_inventory(
    inventory: ClientInventory,
    detections: list[TechnologyDetection],
    *,
    agents_dir: Path | str | None = None,
) -> list[FrameworkSelectionDecision]:
    """Hardcoded platform→framework map (legacy / explicit opt-in only)."""
    available = {fw.id: fw for fw in list_frameworks(agents_dir)}
    decisions: list[FrameworkSelectionDecision] = []

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
                status="blocked",
            )
        )

    conflicted_os = {c.host_id for c in inventory.conflicts if c.fact in {"os_family", "os_name"}}
    unsupported_hosts = {
        d.target_id for d in detections if d.status == "unsupported" and "/" not in d.target_id
    }

    for host in inventory.hosts_without_errors():
        if host.host_id in unsupported_hosts or host.is_unsupported_network_device:
            vendor = (host.vendor or "cisco").lower()
            missing = (f"{vendor}.cli.read",)
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id="cisco_ios",
                    framework_version="",
                    target_id=host.host_id,
                    reason=(
                        f"Unsupported {host.asset_type or 'network_device'} "
                        f"(vendor={host.vendor or vendor}); no registered "
                        f"{missing[0]} capability in this POC"
                    ),
                    status="unsupported",
                    missing_capabilities=missing,
                )
            )
            continue

        if host.host_id in conflicted_os:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id="ubuntu_cis_24_l2",
                    framework_version="",
                    target_id=host.host_id,
                    reason=(
                        "OS evidence conflicts between inventory and discovery; "
                        "operator decision required before OS framework selection"
                    ),
                    status="requires_operator_decision",
                )
            )
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id="windows_server",
                    framework_version="",
                    target_id=host.host_id,
                    reason=(
                        "OS evidence conflicts between inventory and discovery; "
                        "Windows framework not applicable until conflict resolved"
                    ),
                    status="not_applicable",
                )
            )
        elif host.os_family == "linux" or "ubuntu" in (host.os_name or "").lower():
            fw = _pick_available(available, _TECH_FRAMEWORK_PREFERENCES["ubuntu"])
            os_source = next(
                (f.source for f in host.facts if f.fact == "os_family"),
                "inventory",
            )
            if fw is not None:
                decisions.append(
                    FrameworkSelectionDecision(
                        framework_id=fw.id,
                        framework_version=_framework_version(fw),
                        target_id=host.host_id,
                        reason=(
                            f"Linux/Ubuntu host confirmed from {os_source} "
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
                        status="blocked",
                    )
                )
        elif host.os_family == "windows":
            fw = _pick_available(available, _TECH_FRAMEWORK_PREFERENCES["windows_server"])
            os_source = next(
                (f.source for f in host.facts if f.fact == "os_family"),
                "inventory",
            )
            if fw is not None:
                decisions.append(
                    FrameworkSelectionDecision(
                        framework_id=fw.id,
                        framework_version=_framework_version(fw),
                        target_id=host.host_id,
                        reason=(
                            f"Windows Server host confirmed from {os_source} "
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
                        status="blocked",
                    )
                )
        elif not host.os_family:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id="host_facts",
                    framework_version="",
                    target_id=host.host_id,
                    reason="OS unknown after inventory load; discovery/clarification required",
                    status="requires_operator_decision",
                )
            )

        pg_status = detection_status_for(detections, "postgresql", host.host_id)
        pg_target = f"{host.host_id}/postgresql"
        fw = _pick_available(available, _TECH_FRAMEWORK_PREFERENCES["postgresql"])
        if pg_status == "confirmed" and fw is not None:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id=fw.id,
                    framework_version=_framework_version(fw),
                    target_id=pg_target,
                    reason="PostgreSQL service confirmed from inventory or discovery",
                    status="selected",
                )
            )
        elif pg_status in {"suspected", "possible", "probable"}:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id=fw.id if fw else "postgres_cis",
                    framework_version=_framework_version(fw),
                    target_id=pg_target,
                    reason=(
                        f"PostgreSQL evidence is {pg_status} (weak signal only); "
                        "operator confirmation required before framework selection"
                    ),
                    status="requires_operator_decision",
                )
            )
        elif pg_status == "absent":
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id=fw.id if fw else "postgres_cis",
                    framework_version=_framework_version(fw),
                    target_id=pg_target,
                    reason="PostgreSQL not present on host after discovery",
                    status="not_applicable",
                )
            )
        elif pg_status == "unknown":
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id=fw.id if fw else "postgres_cis",
                    framework_version=_framework_version(fw),
                    target_id=pg_target,
                    reason="PostgreSQL presence unknown after discovery failure",
                    status="requires_operator_decision",
                )
            )
        elif any(s.name == "postgresql" for s in host.services) and fw is None:
            decisions.append(
                FrameworkSelectionDecision(
                    framework_id="postgres_cis",
                    framework_version="",
                    target_id=pg_target,
                    reason="PostgreSQL confirmed but postgres framework is unavailable",
                    status="blocked",
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

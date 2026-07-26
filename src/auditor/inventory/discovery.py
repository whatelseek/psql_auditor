"""Read-only infrastructure pre-assessment and inventory reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from auditor.domain.inventory import (
    ClientInventory,
    FactConflict,
    InventoryFact,
    InventoryHost,
    InventoryService,
    ValidationIssue,
)


@dataclass(slots=True)
class DiscoveredHostFacts:
    """Facts collected by read-only SSH/WinRM discovery."""

    host_id: str
    os_name: str = ""
    os_family: str = ""
    hostname: str = ""
    services: list[str] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    evidence_ref: str = ""
    error: str = ""


class DiscoveryCollector(Protocol):
    """Collect read-only host facts for inventory pre-assessment."""

    def discover(self, inventory: ClientInventory) -> list[DiscoveredHostFacts]:
        """Return discovered facts for applicable hosts."""


@dataclass(slots=True)
class StaticDiscoveryCollector:
    """Test/double collector that returns pre-seeded discovery results."""

    results: list[DiscoveredHostFacts] = field(default_factory=list)

    def discover(self, inventory: ClientInventory) -> list[DiscoveredHostFacts]:
        wanted = {h.host_id for h in inventory.hosts}
        return [r for r in self.results if r.host_id in wanted]


@dataclass(slots=True)
class NoopDiscoveryCollector:
    """Default collector when live discovery is unavailable."""

    def discover(self, inventory: ClientInventory) -> list[DiscoveredHostFacts]:
        return []


def _os_family(os_name: str) -> str:
    low = (os_name or "").strip().lower()
    if not low:
        return ""
    if "win" in low:
        return "windows"
    if any(tok in low for tok in ("ubuntu", "debian", "linux", "centos", "rhel", "rocky")):
        return "linux"
    return "unknown"


def reconcile_inventory(
    inventory: ClientInventory,
    discoveries: list[DiscoveredHostFacts],
) -> ClientInventory:
    """Merge discovered facts without overwriting inventory-declared facts.

    Conflicts are recorded on ``conflicts`` and as ``fact_conflict`` issues.
    Confirmed discovery fills missing OS/services with ``source=discovered``.
    """
    by_id = {d.host_id: d for d in discoveries}
    new_hosts: list[InventoryHost] = []
    conflicts: list[FactConflict] = list(inventory.conflicts)
    issues: list[ValidationIssue] = list(inventory.issues)
    all_facts: list[InventoryFact] = []

    for host in inventory.hosts:
        disc = by_id.get(host.host_id)
        if disc is None or disc.error:
            if disc and disc.error:
                issues.append(
                    ValidationIssue(
                        level="warning",
                        code="discovery_failed",
                        message=f"discovery failed for {host.host_id}: {disc.error}",
                        host_id=host.host_id,
                    )
                )
            new_hosts.append(host)
            all_facts.extend(host.facts)
            continue

        disc_os_family = disc.os_family or _os_family(disc.os_name)
        disc_os_name = disc.os_name
        evidence = disc.evidence_ref or f"discovery:{host.host_id}"

        os_name = host.os_name
        os_family = host.os_family
        host_facts = list(host.facts)
        services = list(host.services)
        service_names = {s.name for s in services}

        # OS reconciliation
        if host.os_family and disc_os_family and host.os_family != disc_os_family:
            conflicts.append(
                FactConflict(
                    host_id=host.host_id,
                    fact="os_family",
                    inventory_value=host.os_family,
                    discovered_value=disc_os_family,
                    message=(
                        f"inventory os_family={host.os_family!r} conflicts with "
                        f"discovered {disc_os_family!r}"
                    ),
                )
            )
            issues.append(
                ValidationIssue(
                    level="warning",
                    code="fact_conflict",
                    message=(
                        f"OS conflict on {host.host_id}: inventory={host.os_family}, "
                        f"discovered={disc_os_family}; clarification required"
                    ),
                    host_id=host.host_id,
                    location="os_family",
                )
            )
        elif not host.os_family and disc_os_family:
            os_family = disc_os_family
            os_name = disc_os_name or disc_os_family
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="os_family",
                    value=os_family,
                    source="discovered",
                    confidence=1.0,
                    evidence_ref=evidence,
                )
            )
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="os_name",
                    value=os_name,
                    source="discovered",
                    confidence=1.0,
                    evidence_ref=evidence,
                )
            )
            # Clear needs_discovery for this host.
            issues = [
                i for i in issues if not (i.host_id == host.host_id and i.code == "needs_discovery")
            ]

        # Service reconciliation — inventory services stay; discovery adds missing.
        for svc_name in disc.services:
            name = (svc_name or "").strip().lower()
            if not name:
                continue
            if name == "postgres":
                name = "postgresql"
            if name in service_names:
                continue
            # Port-only signals stay out of confirmed services here; collector
            # should only list confirmed process/package names as services.
            port = 5432 if name == "postgresql" else (22 if name == "ssh" else None)
            if name == "winrm":
                port = 5985
            services.append(
                InventoryService(
                    name=name,
                    port=port,
                    status="confirmed",
                    source="discovered",
                    confidence=1.0,
                )
            )
            service_names.add(name)
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact=f"{name}_installed",
                    value=True,
                    source="discovered",
                    confidence=1.0,
                    evidence_ref=evidence,
                )
            )

        # Weak port-only evidence recorded as facts, not confirmed services.
        for port in disc.listening_ports:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="listening_port",
                    value=port,
                    source="discovered",
                    confidence=0.4,
                    evidence_ref=evidence,
                )
            )

        hostname = host.hostname
        if disc.hostname and host.hostname and disc.hostname.lower() != host.hostname.lower():
            if host.hostname != host.host_id:
                conflicts.append(
                    FactConflict(
                        host_id=host.host_id,
                        fact="hostname",
                        inventory_value=host.hostname,
                        discovered_value=disc.hostname,
                        message="hostname conflict between inventory and discovery",
                    )
                )
        elif disc.hostname and (not host.hostname or host.hostname == host.host_id):
            hostname = disc.hostname

        connection_types = list(host.connection_types)
        if "postgresql" in service_names and "postgresql" not in connection_types:
            connection_types.append("postgresql")

        updated = InventoryHost(
            host_id=host.host_id,
            hostname=hostname,
            address=host.address,
            os_family=os_family,
            os_name=os_name,
            roles=host.roles,
            services=tuple(services),
            connection_types=tuple(connection_types),
            credential_refs=host.credential_refs,
            notes=host.notes,
            facts=tuple(host_facts),
        )
        new_hosts.append(updated)
        all_facts.extend(updated.facts)

    databases = tuple(
        sorted(
            {
                f"{h.host_id}/postgresql"
                for h in new_hosts
                if any(s.name == "postgresql" for s in h.services)
            }
        )
    )
    return inventory.model_copy(
        update={
            "hosts": tuple(new_hosts),
            "facts": tuple(all_facts),
            "conflicts": tuple(conflicts),
            "issues": tuple(issues),
            "databases": databases,
        }
    )

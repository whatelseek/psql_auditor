"""Read-only infrastructure pre-assessment and inventory reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from auditor.domain.inventory import (
    ClientInventory,
    FactConflict,
    InventoryFact,
    InventoryHost,
    InventoryService,
    ValidationIssue,
)
from auditor.inventory.collectors import (
    CompositeDiscoveryCollector,
    DiscoveredHostFacts,
    DiscoveryHostSettings,
    SshDiscoveryCollector,
    WinrmDiscoveryCollector,
    production_discovery_collector,
)
from auditor.inventory.discovery_evidence import utc_now

__all__ = [
    "CompositeDiscoveryCollector",
    "DiscoveredHostFacts",
    "DiscoveryCollector",
    "DiscoveryHostSettings",
    "NoopDiscoveryCollector",
    "SshDiscoveryCollector",
    "StaticDiscoveryCollector",
    "WinrmDiscoveryCollector",
    "default_discovery_collector",
    "production_discovery_collector",
    "reconcile_inventory",
]


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
    """Collector used when discovery is explicitly disabled or unavailable."""

    def discover(self, inventory: ClientInventory) -> list[DiscoveredHostFacts]:
        return []


def default_discovery_collector(
    inventory_dir: Path | str,
    client_name: str,
    *,
    artifacts_root: Path | str | None = None,
    enabled: bool = True,
) -> DiscoveryCollector:
    """Return the production composite collector, or no-op when disabled."""
    if not enabled:
        return NoopDiscoveryCollector()
    return production_discovery_collector(
        inventory_dir,
        client_name,
        artifacts_root=artifacts_root,
    )


def _os_family(os_name: str) -> str:
    low = (os_name or "").strip().lower()
    if not low:
        return ""
    if "win" in low:
        return "windows"
    if any(tok in low for tok in ("ubuntu", "debian", "linux", "centos", "rhel", "rocky")):
        return "linux"
    return "unknown"


def _confidence_score(level: str) -> float:
    mapping = {"high": 1.0, "medium": 0.7, "low": 0.4}
    return mapping.get((level or "high").lower(), 0.7)


def _typed_issue_for_discovery(disc: DiscoveredHostFacts) -> ValidationIssue:
    code = disc.error_code or "discovery_failed"
    level = "warning"
    if code in {"partial_discovery"}:
        level = "information"
    return ValidationIssue(
        level=level,  # type: ignore[arg-type]
        code=code,
        message=(
            f"discovery {code} for {disc.host_id}" + (f": {disc.error}" if disc.error else "")
        ),
        host_id=disc.host_id,
        location="discovery",
    )


def reconcile_inventory(
    inventory: ClientInventory,
    discoveries: list[DiscoveredHostFacts],
) -> ClientInventory:
    """Merge discovered facts without overwriting inventory-declared facts.

    Maintains separate provenance for declared vs discovered facts. Effective
    host fields are filled only from strong discovered facts when declared
    values are missing. Conflicts are recorded and block dependent frameworks.
    """
    by_id = {d.host_id: d for d in discoveries}
    new_hosts: list[InventoryHost] = []
    conflicts: list[FactConflict] = list(inventory.conflicts)
    issues: list[ValidationIssue] = list(inventory.issues)
    all_facts: list[InventoryFact] = []

    for host in inventory.hosts:
        disc = by_id.get(host.host_id)
        if disc is None:
            new_hosts.append(host)
            all_facts.extend(host.facts)
            continue

        # Always preserve the host on failure; record typed limitation.
        if (
            disc.error_code
            and disc.error_code not in {"", "partial_discovery"}
            and not (disc.os_family or disc.services)
        ):
            issues.append(_typed_issue_for_discovery(disc))
            issues.append(
                ValidationIssue(
                    level="information",
                    code="discovery_limitation",
                    message=(
                        f"discovery limitation on {host.host_id}: "
                        f"{disc.error_code}; frameworks requiring unconfirmed "
                        "facts will not be selected"
                    ),
                    host_id=host.host_id,
                    location="discovery",
                )
            )
            # Keep declared facts; attach low-confidence discovered markers.
            host_facts = list(host.facts)
            if disc.evidence_ref:
                host_facts.append(
                    InventoryFact(
                        host_id=host.host_id,
                        fact="discovery_error",
                        value=disc.error_code,
                        source="discovered",
                        confidence=0.0,
                        evidence_ref=disc.evidence_ref,
                    )
                )
            updated = host.model_copy(update={"facts": tuple(host_facts)})
            new_hosts.append(updated)
            all_facts.extend(updated.facts)
            continue

        if disc.error_code == "partial_discovery":
            issues.append(_typed_issue_for_discovery(disc))

        disc_os_family = disc.os_family or _os_family(disc.os_name)
        disc_os_name = disc.os_name
        evidence = disc.evidence_ref or f"discovery:{host.host_id}"
        conf = _confidence_score(disc.confidence)
        collected = disc.collected_at or utc_now()

        os_name = host.os_name
        os_family = host.os_family
        host_facts = list(host.facts)
        services = list(host.services)
        service_names = {s.name for s in services}

        # Always retain discovered OS as a discovered fact (never overwrite declared).
        if disc_os_family:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="os_family",
                    value=disc_os_family,
                    source="discovered",
                    confidence=conf,
                    evidence_ref=evidence,
                )
            )
        if disc_os_name:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="os_name",
                    value=disc_os_name,
                    source="discovered",
                    confidence=conf,
                    evidence_ref=evidence,
                )
            )
        if disc.os_version:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="os_version",
                    value=disc.os_version,
                    source="discovered",
                    confidence=conf,
                    evidence_ref=evidence,
                )
            )
        if disc.hostname:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="hostname",
                    value=disc.hostname,
                    source="discovered",
                    confidence=conf,
                    evidence_ref=evidence,
                )
            )
        if disc.collector:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="connection_transport",
                    value=disc.transport or disc.collector,
                    source="discovered",
                    confidence=1.0,
                    evidence_ref=evidence,
                )
            )
        host_facts.append(
            InventoryFact(
                host_id=host.host_id,
                fact="collected_at",
                value=collected,
                source="discovered",
                confidence=1.0,
                evidence_ref=evidence,
            )
        )

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
        elif not host.os_family and disc_os_family and conf >= 0.7:
            # Strong discovered fact becomes effective when declared is missing.
            os_family = disc_os_family
            os_name = disc_os_name or disc_os_family
            issues = [
                i for i in issues if not (i.host_id == host.host_id and i.code == "needs_discovery")
            ]
        elif not host.os_family and disc_os_family and conf < 0.7:
            # Low confidence — supporting evidence only.
            issues.append(
                ValidationIssue(
                    level="information",
                    code="low_confidence_discovery",
                    message=(
                        f"low-confidence OS discovery on {host.host_id}; "
                        "not used alone for framework selection"
                    ),
                    host_id=host.host_id,
                    location="os_family",
                )
            )

        # Service reconciliation — inventory services stay; discovery adds missing
        # only for confirmed (non-low) service signals.
        for svc_name in disc.services:
            name = (svc_name or "").strip().lower()
            if not name:
                continue
            if name == "postgres":
                name = "postgresql"
            if name in service_names:
                continue
            if conf < 0.7 and name == "postgresql":
                # Low confidence must not confirm PostgreSQL alone.
                host_facts.append(
                    InventoryFact(
                        host_id=host.host_id,
                        fact="postgresql_signal",
                        value="low_confidence",
                        source="discovered",
                        confidence=conf,
                        evidence_ref=evidence,
                    )
                )
                continue
            port = 5432 if name == "postgresql" else (22 if name == "ssh" else None)
            if name == "winrm":
                port = 5985
            services.append(
                InventoryService(
                    name=name,
                    port=port,
                    status="confirmed",
                    source="discovered",
                    confidence=1.0 if conf >= 0.7 else conf,
                )
            )
            service_names.add(name)
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact=f"{name}_installed",
                    value=True,
                    source="discovered",
                    confidence=1.0 if conf >= 0.7 else conf,
                    evidence_ref=evidence,
                )
            )

        for svc_name in disc.running_services:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="running_service",
                    value=svc_name,
                    source="discovered",
                    confidence=conf,
                    evidence_ref=evidence,
                )
            )
        for pkg in disc.postgres_packages:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="postgres_package",
                    value=pkg,
                    source="discovered",
                    confidence=conf,
                    evidence_ref=evidence,
                )
            )
        for proc in disc.postgres_processes:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="postgres_process",
                    value=True,
                    source="discovered",
                    confidence=1.0,
                    evidence_ref=evidence,
                )
            )
        for svc in disc.postgres_services:
            host_facts.append(
                InventoryFact(
                    host_id=host.host_id,
                    fact="postgres_service",
                    value=svc,
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
        if disc.transport and disc.transport not in connection_types:
            # Do not invent connection types from discovery transport alone when
            # inventory already declared a different primary access method.
            pass

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

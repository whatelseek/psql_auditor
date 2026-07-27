"""Normalized fact namespace for dynamic framework selection (INPUT-005)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictStr

from auditor.domain.inventory import ClientInventory, InventoryHost, TechnologyDetection


class NormalizedFact(BaseModel):
    """One evidence-backed fact in the stable INPUT-005 namespace."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fact: StrictStr = Field(min_length=1)
    value: object
    confidence: StrictFloat = 1.0
    source: StrictStr = "inventory"
    evidence_ref: StrictStr = ""


class HostFactSet(BaseModel):
    """Normalized facts for one host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host_id: StrictStr
    facts: tuple[NormalizedFact, ...] = ()

    def as_map(self) -> dict[str, object]:
        return {f.fact: f.value for f in self.facts}

    def get(self, key: str, default: object = None) -> object:
        for item in self.facts:
            if item.fact == key:
                return item.value
        return default


def build_host_fact_set(
    host: InventoryHost,
    *,
    detections: list[TechnologyDetection] | None = None,
    extra_facts: list[NormalizedFact] | None = None,
) -> HostFactSet:
    """Build the stable fact namespace for one inventory host."""
    rows: list[NormalizedFact] = []
    rows.append(
        NormalizedFact(fact="asset.id", value=host.host_id, source="inventory", confidence=1.0)
    )
    if host.asset_type:
        rows.append(
            NormalizedFact(
                fact="asset.type", value=host.asset_type, source="inventory", confidence=1.0
            )
        )
    if host.vendor:
        rows.append(
            NormalizedFact(
                fact="asset.vendor", value=host.vendor.lower(), source="inventory", confidence=1.0
            )
        )
    for role in host.roles:
        rows.append(
            NormalizedFact(fact="asset.role", value=role, source="inventory", confidence=1.0)
        )

    if host.os_family:
        rows.append(
            NormalizedFact(
                fact="os.family",
                value=host.os_family.lower(),
                source=_fact_source(host, "os_family"),
                confidence=1.0,
            )
        )
    dist = _distribution(host)
    if dist:
        rows.append(
            NormalizedFact(
                fact="os.distribution",
                value=dist,
                source=_fact_source(host, "os_name") if host.os_name else "inventory",
                confidence=1.0,
            )
        )
    if host.os_name:
        rows.append(
            NormalizedFact(
                fact="os.version",
                value=host.os_name,
                source=_fact_source(host, "os_name"),
                confidence=0.8,
            )
        )

    if "ssh" in host.connection_types:
        rows.append(
            NormalizedFact(
                fact="access.ssh.available", value=True, source="inventory", confidence=1.0
            )
        )
    if "winrm" in host.connection_types:
        rows.append(
            NormalizedFact(
                fact="access.winrm.available", value=True, source="inventory", confidence=1.0
            )
        )

    ports: set[int] = set()
    for svc in host.services:
        if svc.port is not None:
            ports.add(int(svc.port))
        status = svc.status if svc.status in {"confirmed", "suspected", "absent"} else "confirmed"
        rows.append(
            NormalizedFact(
                fact=f"service.{svc.name}.status",
                value=status,
                source=svc.source,
                confidence=float(svc.confidence),
            )
        )
        if svc.name == "postgresql" and svc.status:
            rows.append(
                NormalizedFact(
                    fact="technology.postgresql.status",
                    value=status,
                    source=svc.source,
                    confidence=float(svc.confidence),
                )
            )
    for item in host.facts:
        if item.fact == "listening_port" and isinstance(item.value, int):
            ports.add(int(item.value))
    for port in sorted(ports):
        rows.append(
            NormalizedFact(
                fact=f"port.{port}.status",
                value="open",
                source="discovered",
                confidence=0.7,
            )
        )

    for det in detections or []:
        if det.target_id != host.host_id and not det.target_id.startswith(f"{host.host_id}/"):
            continue
        tech = det.technology_id
        rows.append(
            NormalizedFact(
                fact=f"technology.{tech}.status",
                value=det.status,
                source=det.source,
                confidence=float(det.confidence),
                evidence_ref=";".join(det.evidence) if det.evidence else "",
            )
        )
        # Map OS tech detections onto os.* when helpful.
        if tech in {"ubuntu", "linux"} and "os.family" not in {r.fact for r in rows}:
            rows.append(
                NormalizedFact(
                    fact="os.family",
                    value="linux",
                    source=det.source,
                    confidence=float(det.confidence),
                )
            )
        if tech == "ubuntu" and "os.distribution" not in {r.fact for r in rows}:
            rows.append(
                NormalizedFact(
                    fact="os.distribution",
                    value="ubuntu",
                    source=det.source,
                    confidence=float(det.confidence),
                )
            )
        if tech == "windows_server" and "os.family" not in {r.fact for r in rows}:
            rows.append(
                NormalizedFact(
                    fact="os.family",
                    value="windows",
                    source=det.source,
                    confidence=float(det.confidence),
                )
            )

    if extra_facts:
        rows.extend(extra_facts)

    # Last-write-wins by fact key (extra/discovery overrides inventory).
    by_key: dict[str, NormalizedFact] = {}
    for row in rows:
        by_key[row.fact] = row
    ordered = tuple(by_key[k] for k in sorted(by_key))
    return HostFactSet(host_id=host.host_id, facts=ordered)


def build_inventory_fact_sets(
    inventory: ClientInventory,
    detections: list[TechnologyDetection],
    *,
    extras: dict[str, list[NormalizedFact]] | None = None,
) -> dict[str, HostFactSet]:
    """Build fact sets for all hosts in inventory."""
    out: dict[str, HostFactSet] = {}
    for host in inventory.hosts:
        out[host.host_id] = build_host_fact_set(
            host,
            detections=detections,
            extra_facts=(extras or {}).get(host.host_id),
        )
    return out


def merge_facts(base: HostFactSet, new_facts: list[NormalizedFact]) -> HostFactSet:
    """Return a new fact set with ``new_facts`` overlaying ``base``."""
    by_key = {f.fact: f for f in base.facts}
    for item in new_facts:
        by_key[item.fact] = item
    return HostFactSet(
        host_id=base.host_id,
        facts=tuple(by_key[k] for k in sorted(by_key)),
    )


def _distribution(host: InventoryHost) -> str:
    name = (host.os_name or "").lower()
    for token in ("ubuntu", "debian", "centos", "rhel", "rocky", "fedora", "suse", "windows"):
        if token in name:
            return token
    if host.os_family == "linux" and "ubuntu" in (host.hostname or "").lower():
        return "ubuntu"
    if host.os_family == "windows":
        return "windows"
    return ""


def _fact_source(host: InventoryHost, fact_name: str) -> str:
    for item in host.facts:
        if item.fact == fact_name:
            return item.source
    return "inventory"


def facts_to_serializable(fact_sets: dict[str, HostFactSet]) -> dict[str, Any]:
    """JSON-friendly dump of normalized facts (secret-free)."""
    return {
        host_id: [f.model_dump() for f in fact_set.facts]
        for host_id, fact_set in sorted(fact_sets.items())
    }

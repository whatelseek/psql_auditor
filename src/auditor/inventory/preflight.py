"""Deterministic preflight revisions for inventory discovery."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auditor.domain.inventory import ClientInventory, InventoryFact
from auditor.inventory.discovery_evidence import COLLECTOR_VERSION

# Volatile keys excluded from effective / discovery result hashes.
_VOLATILE_KEYS = frozenset(
    {
        "collected_at",
        "created_at",
        "stdout",
        "stderr",
        "command",
        "exit_code",
        "error",
        "commands",
        "command_results",
    }
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _stable_dump(value: Any) -> Any:
    """Recursively drop volatile keys and normalize for hashing."""
    if isinstance(value, dict):
        return {
            str(k): _stable_dump(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
            if str(k) not in _VOLATILE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_stable_dump(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def stable_hash(payload: Any) -> str:
    """SHA-256 of a normalized JSON payload."""
    blob = json.dumps(_stable_dump(payload), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def discovery_result_hash(discoveries: list[Any]) -> str:
    """Hash normalized discovery results (host facts without volatile fields)."""
    rows: list[dict[str, Any]] = []
    for item in discoveries:
        if hasattr(item, "__dataclass_fields__"):
            data = asdict(item)
        elif isinstance(item, dict):
            data = dict(item)
        else:
            data = {"value": str(item)}
        # Drop command payloads; keep structural facts only.
        data.pop("command_results", None)
        data.pop("commands", None)
        rows.append(data)
    rows.sort(key=lambda r: str(r.get("host_id") or ""))
    return stable_hash(rows)


def effective_facts_hash(inventory: ClientInventory) -> str:
    """Hash effective host facts used for framework selection."""
    rows: list[dict[str, Any]] = []
    for host in inventory.hosts:
        rows.append(
            {
                "host_id": host.host_id,
                "os_family": host.os_family,
                "os_name": host.os_name,
                "hostname": host.hostname,
                "services": sorted(
                    {
                        f"{s.name}:{s.status}:{s.source}:{round(float(s.confidence), 2)}"
                        for s in host.services
                    }
                ),
                "connection_types": list(host.connection_types),
                "facts": _fact_rows(host.facts),
            }
        )
    rows.sort(key=lambda r: r["host_id"])
    conflicts = [
        {
            "host_id": c.host_id,
            "fact": c.fact,
            "inventory_value": c.inventory_value,
            "discovered_value": c.discovered_value,
        }
        for c in inventory.conflicts
    ]
    conflicts.sort(key=lambda c: (c["host_id"], c["fact"]))
    return stable_hash({"hosts": rows, "conflicts": conflicts})


def _fact_rows(facts: tuple[InventoryFact, ...]) -> list[dict[str, Any]]:
    rows = [
        {
            "fact": f.fact,
            "value": f.value,
            "source": f.source,
            "confidence": round(float(f.confidence), 2),
        }
        for f in facts
        # Exclude listening_port noise from volatility of command ordering —
        # ports are still included but sorted.
        if f.fact != "listening_port" or True
    ]
    rows.sort(key=lambda r: (r["fact"], json.dumps(r["value"], sort_keys=True, default=str)))
    return rows


@dataclass(slots=True)
class PreflightRevision:
    """Immutable preflight snapshot identity."""

    revision_id: str
    inventory_version_id: str
    inventory_content_hash: str
    discovery_result_hash: str
    effective_facts_hash: str
    selected_frameworks: list[str] = field(default_factory=list)
    collector_versions: dict[str, str] = field(default_factory=dict)
    created_at: str = ""
    client_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision_id": self.revision_id,
            "client_id": self.client_id,
            "inventory_version_id": self.inventory_version_id,
            "inventory_content_hash": self.inventory_content_hash,
            "discovery_result_hash": self.discovery_result_hash,
            "effective_facts_hash": self.effective_facts_hash,
            "selected_frameworks": list(self.selected_frameworks),
            "collector_versions": dict(self.collector_versions),
            "created_at": self.created_at,
        }


def build_preflight_revision(
    inventory: ClientInventory,
    *,
    discoveries: list[Any],
    selected_frameworks: list[str],
    collector_versions: dict[str, str] | None = None,
    created_at: str | None = None,
) -> PreflightRevision:
    """Build a deterministic preflight revision for the analyze result."""
    disc_hash = discovery_result_hash(discoveries)
    eff_hash = effective_facts_hash(inventory)
    versions = collector_versions or {"composite": COLLECTOR_VERSION}
    revision_id = (
        "preflight-"
        + stable_hash(
            {
                "inventory_version_id": inventory.version.version_id,
                "inventory_content_hash": inventory.version.content_hash,
                "discovery_result_hash": disc_hash,
                "effective_facts_hash": eff_hash,
                "selected_frameworks": sorted(selected_frameworks),
                "collector_versions": versions,
            }
        )[:16]
    )
    return PreflightRevision(
        revision_id=revision_id,
        client_id=inventory.client_id,
        inventory_version_id=inventory.version.version_id,
        inventory_content_hash=inventory.version.content_hash,
        discovery_result_hash=disc_hash,
        effective_facts_hash=eff_hash,
        selected_frameworks=sorted(selected_frameworks),
        collector_versions=versions,
        created_at=created_at or _utc_now(),
    )


def persist_preflight_revision(
    revision: PreflightRevision,
    *,
    artifacts_root: Path | str,
    client_slug: str,
) -> Path:
    """Persist preflight revision under ``artifacts/<slug>/preflight/``."""
    root = Path(artifacts_root) / client_slug / "preflight"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{revision.revision_id}.json"
    path.write_text(
        json.dumps(revision.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    latest = root / "latest.json"
    latest.write_text(
        json.dumps(revision.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def load_latest_preflight(
    artifacts_root: Path | str,
    client_slug: str,
) -> PreflightRevision | None:
    """Load the latest persisted preflight revision, if any."""
    path = Path(artifacts_root) / client_slug / "preflight" / "latest.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return PreflightRevision(
        revision_id=str(data.get("revision_id") or ""),
        client_id=str(data.get("client_id") or ""),
        inventory_version_id=str(data.get("inventory_version_id") or ""),
        inventory_content_hash=str(data.get("inventory_content_hash") or ""),
        discovery_result_hash=str(data.get("discovery_result_hash") or ""),
        effective_facts_hash=str(data.get("effective_facts_hash") or ""),
        selected_frameworks=list(data.get("selected_frameworks") or []),
        collector_versions=dict(data.get("collector_versions") or {}),
        created_at=str(data.get("created_at") or ""),
    )

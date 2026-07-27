"""Capability-based discovery planning (INPUT-005)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from auditor.domain.applicability import DiscoveryHint
from auditor.domain.normalized_facts import HostFactSet
from auditor.inventory.framework_candidates import FrameworkCandidate
from auditor.inventory.framework_meta import (
    list_frameworks_with_meta,
)
from auditor.tool_registry import ToolManifest, ToolRegistry, get_tool_registry


class DiscoveryStep(BaseModel):
    """One registry-driven discovery step (capability request, not a client)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: StrictStr = Field(min_length=1)
    host_id: StrictStr = Field(min_length=1)
    capability: StrictStr = Field(min_length=1)
    purpose: StrictStr = ""
    arguments: dict[str, object] = Field(default_factory=dict)
    expected_facts: tuple[StrictStr, ...] = ()
    timeout_seconds: StrictInt = 10
    framework_id: StrictStr = ""
    status: StrictStr = "planned"  # planned | blocked | completed
    missing_capability: StrictStr = ""
    reason: StrictStr = ""
    tool_id: StrictStr = ""


class DiscoveryPlan(BaseModel):
    """Ordered capability requests for missing evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: StrictStr
    steps: tuple[DiscoveryStep, ...] = ()


def build_discovery_plan(
    candidates: list[FrameworkCandidate],
    host_facts: dict[str, HostFactSet],
    *,
    agents_dir: Path | str | None = None,
    registry: ToolRegistry | None = None,
    max_ports_per_host: int = 20,
) -> DiscoveryPlan:
    """Generate bounded discovery steps for candidates needing evidence.

    Skips frameworks already ``not_matched``. Requests capabilities via
    framework ``discovery_hints`` and missing fact heuristics. Never invents
    targets or credentials.
    """
    reg = registry or get_tool_registry()
    meta_by_id = {fw.id: meta for fw, meta in list_frameworks_with_meta(agents_dir)}
    steps: list[DiscoveryStep] = []
    seen: set[tuple[str, str, str]] = set()  # host, capability, args-hash

    for candidate in candidates:
        if candidate.predicate_result == "not_matched":
            continue
        if candidate.predicate_result not in {"missing_evidence", "matched"}:
            # Still allow capability probes when matched but required_facts missing
            if not candidate.missing_facts:
                continue
        meta = meta_by_id.get(candidate.framework_id)
        if meta is None:
            continue
        hints = list(meta.discovery_hints)
        if not hints and candidate.missing_facts:
            hints = _heuristic_hints(candidate.missing_facts)

        for hint in hints:
            args = dict(hint.arguments or {})
            # Enforce TCP port bounds / inventory-declared ports only.
            if hint.capability == "tcp.connect":
                ports = _bounded_ports(
                    args.get("ports"),
                    host_facts.get(candidate.host_id),
                    max_ports=max_ports_per_host,
                )
                if not ports:
                    continue
                args["ports"] = ports
            arg_key = hashlib.sha256(
                json.dumps(args, sort_keys=True, default=str).encode()
            ).hexdigest()[:10]
            dedupe = (candidate.host_id, hint.capability, arg_key)
            if dedupe in seen:
                continue
            seen.add(dedupe)

            tool = select_tool_for_capability(hint.capability, registry=reg)
            if tool is None:
                steps.append(
                    DiscoveryStep(
                        step_id=_step_id(candidate.host_id, hint.capability, arg_key),
                        host_id=candidate.host_id,
                        capability=hint.capability,
                        purpose=hint.purpose or f"Collect evidence for {candidate.framework_id}",
                        arguments=args,
                        expected_facts=tuple(hint.expected_facts)
                        or tuple(candidate.missing_facts[:8]),
                        timeout_seconds=10,
                        framework_id=candidate.framework_id,
                        status="blocked",
                        missing_capability=hint.capability,
                        reason="No authorized executable tool is available",
                    )
                )
                continue

            steps.append(
                DiscoveryStep(
                    step_id=_step_id(candidate.host_id, hint.capability, arg_key),
                    host_id=candidate.host_id,
                    capability=hint.capability,
                    purpose=hint.purpose or f"Collect evidence for {candidate.framework_id}",
                    arguments=args,
                    expected_facts=tuple(hint.expected_facts) or tuple(candidate.missing_facts[:8]),
                    timeout_seconds=int(tool.timeout_seconds or 10),
                    framework_id=candidate.framework_id,
                    status="planned",
                    tool_id=tool.id,
                )
            )

    steps.sort(key=lambda s: (s.host_id, s.capability, s.step_id))
    digest = hashlib.sha256(
        json.dumps([s.model_dump() for s in steps], sort_keys=True, default=str).encode()
    ).hexdigest()
    return DiscoveryPlan(plan_id=f"dplan-{digest[:12]}", steps=tuple(steps))


def select_tool_for_capability(
    capability: str,
    *,
    registry: ToolRegistry | None = None,
) -> ToolManifest | None:
    """Fail-closed tool selection for a required capability."""
    reg = registry or get_tool_registry()
    matches = [t for t in reg.authorized_tools() if capability in t.capabilities and t.executable]
    if not matches:
        return None
    matches.sort(key=lambda t: (t.id, t.version))
    return matches[0]


def _step_id(host_id: str, capability: str, arg_key: str) -> str:
    return f"disc-{host_id}-{capability.replace('.', '-')}-{arg_key}"


def _bounded_ports(
    raw: object,
    fact_set: HostFactSet | None,
    *,
    max_ports: int,
) -> list[int]:
    ports: list[int] = []
    if isinstance(raw, list):
        for item in raw:
            try:
                ports.append(int(item))
            except (TypeError, ValueError):
                continue
    # Intersect with inventory-declared / already known listening ports when present.
    known: set[int] = set()
    if fact_set is not None:
        for fact, value in fact_set.as_map().items():
            if fact.startswith("port.") and fact.endswith(".status"):
                try:
                    known.add(int(fact.split(".")[1]))
                except (IndexError, ValueError):
                    pass
    if known and ports:
        ports = [p for p in ports if p in known]
    # If framework asks for ports not yet known, still allow explicitly declared
    # discovery-hint ports (framework metadata), capped.
    out: list[int] = []
    for p in ports:
        if 1 <= p <= 65535 and p not in out:
            out.append(p)
        if len(out) >= max_ports:
            break
    return out


def _heuristic_hints(missing_facts: tuple[str, ...] | list[str]) -> list[DiscoveryHint]:
    hints: list[DiscoveryHint] = []
    for fact in missing_facts:
        if fact.startswith("port.") and fact.endswith(".status"):
            try:
                port = int(fact.split(".")[1])
            except (IndexError, ValueError):
                continue
            hints.append(
                DiscoveryHint(
                    capability="tcp.connect",
                    purpose=f"Check listener on port {port}",
                    arguments={"ports": [port]},
                    expected_facts=(fact,),
                )
            )
        elif fact.startswith("technology.postgresql"):
            hints.append(
                DiscoveryHint(
                    capability="ssh.command.read",
                    purpose="Confirm PostgreSQL installation",
                    operation_ids=(
                        "detect_postgresql_binary",
                        "detect_postgresql_service",
                        "read_postgresql_version",
                    ),
                    expected_facts=(
                        "technology.postgresql.status",
                        "technology.postgresql.version",
                    ),
                )
            )
        elif fact.startswith("http."):
            hints.append(
                DiscoveryHint(
                    capability="http.get",
                    purpose="Collect HTTP response facts",
                    arguments={"method": "HEAD", "path": "/"},
                    expected_facts=(fact,),
                )
            )
        elif fact.startswith("asset.vendor") or fact.startswith("os.family"):
            hints.append(
                DiscoveryHint(
                    capability="snmp.get",
                    purpose="Read device identity via SNMP",
                    arguments={"oids": ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"]},
                    expected_facts=(fact,),
                )
            )
    return hints


def discovery_plan_to_dict(plan: DiscoveryPlan) -> dict[str, Any]:
    return plan.model_dump()

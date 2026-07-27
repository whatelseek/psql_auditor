"""Execute capability-based discovery steps through ToolRegistry only."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from auditor.domain.normalized_facts import NormalizedFact
from auditor.domain.tool_result import ToolResult
from auditor.inventory.discovery_plan import (
    DiscoveryPlan,
    DiscoveryStep,
    select_tool_for_capability,
)
from auditor.secrets_file import InventorySshTarget, bind_ssh_target
from auditor.tool_registry import get_tool_registry


async def execute_discovery_step(
    step: DiscoveryStep,
    *,
    target_host: str,
    target_port: int | None = None,
) -> tuple[DiscoveryStep, ToolResult | None, list[NormalizedFact]]:
    """Run one discovery step via the registered adapter (fail-closed)."""
    if step.status == "blocked":
        return step, None, []

    registry = get_tool_registry()
    tool = select_tool_for_capability(step.capability, registry=registry)
    if tool is None:
        blocked = step.model_copy(
            update={
                "status": "blocked",
                "missing_capability": step.capability,
                "reason": "No authorized executable tool is available",
            }
        )
        return blocked, None, []

    # Resolve adapter invoke callable.
    module_name, _, attr = tool.adapter.partition(":")
    import importlib

    module = importlib.import_module(module_name)
    invoke = getattr(module, attr, None)
    if invoke is None or not callable(invoke):
        blocked = step.model_copy(
            update={
                "status": "blocked",
                "reason": f"adapter {tool.adapter!r} is not executable",
            }
        )
        return blocked, None, []

    cred = InventorySshTarget(
        host=target_host,
        port=str(target_port or 22),
        user="discovery",
        password="",
        asset_id=step.host_id,
    )
    args = dict(step.arguments)
    with bind_ssh_target(cred):
        result = await invoke(**args)

    facts = _normalize(step, result)
    completed = step.model_copy(
        update={"status": "completed" if result.status == "ok" else "blocked", "tool_id": tool.id}
    )
    return completed, result, facts


def execute_discovery_plan_sync(
    plan: DiscoveryPlan,
    *,
    host_addresses: dict[str, str],
) -> tuple[DiscoveryPlan, dict[str, list[NormalizedFact]], list[dict[str, Any]]]:
    """Synchronously execute planned steps; return facts and invocation records."""

    async def _run() -> tuple[list[DiscoveryStep], dict[str, list[NormalizedFact]], list[dict]]:
        steps_out: list[DiscoveryStep] = []
        facts_by_host: dict[str, list[NormalizedFact]] = {}
        invocations: list[dict[str, Any]] = []
        for step in plan.steps:
            addr = host_addresses.get(step.host_id, "")
            if not addr and step.status != "blocked":
                steps_out.append(
                    step.model_copy(
                        update={
                            "status": "blocked",
                            "reason": "host address not in inventory scope",
                        }
                    )
                )
                continue
            completed, result, facts = await execute_discovery_step(step, target_host=addr)
            steps_out.append(completed)
            if facts:
                facts_by_host.setdefault(step.host_id, []).extend(facts)
            if result is not None:
                invocations.append(
                    {
                        "host_id": step.host_id,
                        "tool_id": result.tool_id,
                        "tool_version": result.tool_version,
                        "capability": step.capability,
                        "status": result.status,
                        "evidence_ref": f"evidence://preflight/{step.host_id}/{step.step_id}",
                        "started_at": result.started_at,
                        "finished_at": result.finished_at,
                        "provenance": result.provenance.model_dump(),
                    }
                )
        return steps_out, facts_by_host, invocations

    steps, facts, invocations = asyncio.run(_run())
    return (
        DiscoveryPlan(plan_id=plan.plan_id, steps=tuple(steps)),
        facts,
        invocations,
    )


def persist_discovery_artifacts(
    *,
    artifacts_root: Path | str,
    client_slug: str,
    inventory_version_id: str,
    candidates: list[Any],
    discovery_plan: DiscoveryPlan,
    fact_sets: dict[str, Any],
    invocations: list[dict[str, Any]],
) -> Path:
    """Persist candidate evaluations, discovery plan, facts, and invocations."""
    root = Path(artifacts_root) / client_slug / "preflight" / inventory_version_id / "_selection"
    root.mkdir(parents=True, exist_ok=True)
    (root / "framework_candidates.json").write_text(
        json.dumps(
            [c.model_dump() if hasattr(c, "model_dump") else c for c in candidates],
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "discovery_plan.json").write_text(
        json.dumps(discovery_plan.model_dump(), indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    serial_facts = {
        hid: [f.model_dump() if hasattr(f, "model_dump") else f for f in facts]
        for hid, facts in sorted(fact_sets.items())
    }
    (root / "normalized_facts.json").write_text(
        json.dumps(serial_facts, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    (root / "tool_invocations.json").write_text(
        json.dumps(invocations, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    return root


def _normalize(step: DiscoveryStep, result: ToolResult) -> list[NormalizedFact]:
    from auditor.tools.http_get import normalize_http_get_result
    from auditor.tools.snmp import normalize_snmp_get_result
    from auditor.tools.tcp_connect import normalize_tcp_connect_result

    ref = f"evidence://preflight/{step.host_id}/{step.step_id}"
    raw: list[dict[str, object]]
    if step.capability == "tcp.connect":
        raw = normalize_tcp_connect_result(result, host_id=step.host_id, evidence_ref=ref)
    elif step.capability == "http.get":
        raw = normalize_http_get_result(result, host_id=step.host_id, evidence_ref=ref)
    elif step.capability in {"snmp.get", "snmp.walk"}:
        raw = normalize_snmp_get_result(result, host_id=step.host_id, evidence_ref=ref)
    else:
        raw = []
    out: list[NormalizedFact] = []
    for item in raw:
        out.append(
            NormalizedFact(
                fact=str(item["fact"]),
                value=item["value"],
                confidence=float(item.get("confidence") or 0.5),
                source=str(item.get("source") or step.tool_id or step.capability),
                evidence_ref=str(item.get("evidence_ref") or ref),
            )
        )
    return out

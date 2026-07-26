"""Prove concurrent ContextVar credential overlays do not leak across tasks."""

from __future__ import annotations

import asyncio

import pytest

from auditor.runtime_target import bind_runtime_credentials, effective_settings


@pytest.mark.asyncio
async def test_concurrent_runtime_credentials_isolated():
    seen: dict[str, str | None] = {}

    async def _worker(label: str, host: str) -> None:
        with bind_runtime_credentials(
            {
                "PG_HOST": host,
                "PG_USER": "u",
                "PG_PASSWORD": "p",
                "PG_DATABASE": "db",
            }
        ):
            await asyncio.sleep(0.02)
            seen[label] = effective_settings().pg_host

    await asyncio.gather(
        _worker("a", "10.0.0.1"),
        _worker("b", "10.0.0.2"),
    )
    assert seen["a"] == "10.0.0.1"
    assert seen["b"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_evidence_registry_isolation(tmp_path):
    from auditor.evidence_store import EvidenceStore
    from auditor.workflows.dependencies import EvidenceRegistry

    reg = EvidenceRegistry()
    a = EvidenceStore(tmp_path, run_id="run-a")
    b = EvidenceStore(tmp_path, run_id="run-b")
    reg["run-a"] = a
    reg["run-b"] = b
    assert reg.get("run-a") is a
    assert reg.get("run-b") is b
    assert reg.get("run-a") is not reg.get("run-b")

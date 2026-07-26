"""Test helpers for INPUT-001 AuditRequest stubs."""

from __future__ import annotations

from typing import Any

from auditor.domain import POC_TOOL_PROFILE


def stub_audit_request(
    client_id: str,
    *,
    host: str = "h1",
    framework_id: str = "fw1",
    framework_version: str = "1.0",
    slug: str = "acme",
) -> dict[str, Any]:
    """Minimal structurally valid AuditRequest dump for unit tests."""
    return {
        "schema_version": 1,
        "client_id": client_id,
        "inventory": {"kind": "client_file", "ref": f"{slug}/INVENTORY.md"},
        "targets": [
            {
                "inventory_target_ref": host,
                "frameworks": [
                    {
                        "framework_id": framework_id,
                        "framework_version": framework_version,
                    }
                ],
            }
        ],
        "tool_profile": POC_TOOL_PROFILE,
        "run_settings": {
            "report_language": "en",
            "hitl_enabled": False,
            "archive_enabled": False,
            "max_parallel_assessments": 5,
            "max_parallel_host_jobs": 2,
        },
    }


def intake_with_request(
    client_id: str,
    *,
    client_name: str = "Acme",
    client_slug: str = "acme",
    host: str = "h1",
    framework_id: str = "fw1",
    **extra: Any,
) -> dict[str, Any]:
    """intake_state dict including a stub AuditRequest for job bootstrap."""
    out: dict[str, Any] = {
        "client_name": client_name,
        "client_slug": client_slug,
        "client_id": client_id,
        "intake_complete": True,
        "audit_request": stub_audit_request(
            client_id, host=host, framework_id=framework_id, slug=client_slug
        ),
    }
    out.update(extra)
    return out

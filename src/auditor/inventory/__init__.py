"""Inventory-driven audit launch package (INPUT-003 / INPUT-005)."""

from __future__ import annotations

from auditor.inventory.client_name import InvalidClientNameError, validate_client_name
from auditor.inventory.collectors import (
    CompositeDiscoveryCollector,
    SshDiscoveryCollector,
    WinrmDiscoveryCollector,
    production_discovery_collector,
)
from auditor.inventory.discovery import (
    DiscoveredHostFacts,
    NoopDiscoveryCollector,
    StaticDiscoveryCollector,
    default_discovery_collector,
    reconcile_inventory,
)
from auditor.inventory.service import (
    analyze_client_inventory,
    astart_confirmed_audit,
    confirm_audit_plan,
    generate_audit_plan,
    load_client_inventory,
    plan_to_audit_request_payload,
    reject_audit_launch,
    start_confirmed_audit,
    validate_client_inventory,
)

__all__ = [
    "CompositeDiscoveryCollector",
    "DiscoveredHostFacts",
    "InvalidClientNameError",
    "NoopDiscoveryCollector",
    "SshDiscoveryCollector",
    "StaticDiscoveryCollector",
    "WinrmDiscoveryCollector",
    "analyze_client_inventory",
    "astart_confirmed_audit",
    "confirm_audit_plan",
    "default_discovery_collector",
    "generate_audit_plan",
    "load_client_inventory",
    "plan_to_audit_request_payload",
    "production_discovery_collector",
    "reconcile_inventory",
    "reject_audit_launch",
    "start_confirmed_audit",
    "validate_client_inventory",
    "validate_client_name",
]

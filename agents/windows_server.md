---
id: windows_server
aliases: [windows, windows server, winrm, windows-cis, win]
description: Windows Server baseline audit checklist (WinRM)
domain: cybersecurity
language: en
family_id: windows_server
detect:
  os_ids: [windows]
version: "1.0"

applicability:
  all:
    - fact: os.family
      operator: equals
      value: windows

required_facts:
  - os.family

target:
  scope: host
---
# Windows Server Security Audit Checklist

Operational checklist for Windows Server targets reachable over WinRM.
Prefer read-only inspection; do not invent values.

## REQ-001: Host identity
**Category:** Inventory
**Severity:** High
**How to verify:** Collect computer name, domain/workgroup, and OS caption via WinRM.
**Pass criteria:** Hostname and Windows Server version are recorded in evidence.

## REQ-002: WinRM access control
**Category:** Access Control
**Severity:** High
**How to verify:** Confirm WinRM listeners and that administrative access uses approved accounts only.
**Pass criteria:** WinRM is restricted to approved management networks/accounts.

## REQ-003: Local administrator membership
**Category:** Access Control
**Severity:** Critical
**How to verify:** Enumerate local Administrators group members.
**Pass criteria:** Only approved privileged accounts remain in Administrators.

## REQ-004: Windows Update status
**Category:** Patch Management
**Severity:** High
**How to verify:** Query installed hotfixes / update status via WinRM.
**Pass criteria:** Critical security updates are installed within the approved window.

## REQ-005: Firewall profile
**Category:** Network
**Severity:** Medium
**How to verify:** Inspect Windows Firewall profiles and enabled state.
**Pass criteria:** Firewall is enabled for the active network profile.

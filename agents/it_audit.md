---
id: it_audit
aliases: [it, it audit, inventory, baseline, host inventory]
description: IT audit — inventory, access, baseline CPU/RAM/disk, CMDB consistency
domain: it
detect:
  always: true
---
# IT Audit (inventory & baseline)

Inventory and baseline IT controls for the engagement host. Complements CIS
checklists. Prefer deterministic SSH / NetBox / Postgres MCP tools.

## REQ-001: Inventory completeness
**Category:** Inventory
**Severity:** High
**How to verify:** Collect hostname and IPs via SSH (`hostname -f`, `hostname -I` / `ip -4 addr`). Record location/owner from NetBox when CMDB is available, otherwise from INVENTORY.md.
**Pass criteria:** Hostname and at least one non-loopback IPv4 address are recorded in evidence.

## REQ-002: Access methods verified
**Category:** Access
**Severity:** Critical
**How to verify:** Probe SSH (`echo ok`), Postgres MCP (`SELECT current_user`), note WinRM status (not configured unless a WinRM client is present).
**Pass criteria:** At least one required access method for the engagement (SSH and/or Postgres) succeeds; failures are documented.

## REQ-003: Baseline CPU
**Category:** Capacity
**Severity:** Medium
**How to verify:** SSH: `nproc`; `lscpu` (model name / CPU count).
**Pass criteria:** CPU count and model are captured. Flag if `nproc` is 0 or command fails.

## REQ-004: Baseline RAM
**Category:** Capacity
**Severity:** Medium
**How to verify:** SSH: `free -m`; `/proc/meminfo` MemTotal/MemAvailable.
**Pass criteria:** Total and available memory are recorded. Flag if MemAvailable is under 10% of MemTotal (partial) or free fails (error).

## REQ-005: Baseline disk free space
**Category:** Capacity
**Severity:** High
**How to verify:** SSH: `df -h` for `/` and data mounts.
**Pass criteria:** Root filesystem free space is recorded. Fail if root use ≥ 90%; partial if ≥ 80%.

## REQ-006: CMDB consistency (NetBox)
**Category:** CMDB
**Severity:** High
**How to verify:** When CMDB is enabled, compare live hostname/IPs to NetBox device (`netbox_get_objects` devices by name). When no CMDB, confirm INVENTORY.md was written for this client.
**Pass criteria:** With CMDB: hostname and primary IP match NetBox (pass), mismatches highlighted (fail). Without CMDB: INVENTORY.md exists under the run artifacts (pass) or is missing (fail).

## REQ-007: Service reachability summary
**Category:** Access
**Severity:** Medium
**How to verify:** Summarize intake access probe results (SSH, Postgres MCP, WinRM).
**Pass criteria:** Reachable vs failed services are listed in observation; at least the in-scope services are attempted when access was granted.

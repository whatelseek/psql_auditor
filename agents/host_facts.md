---
id: host_facts
aliases: [host facts, host inventory, facts, system inventory, baseline inventory]
description: Host inventory facts — OS, hardware, storage, network, services, software
domain: it
language: en
family_id: host_facts
detect:
  always: true
version: "1.0"
---
# Host Facts Inventory Checklist

Deep host inventory for engagement baselines. Complements CIS checklists.
Prefer SSH tools; do not invent values.

## REQ-001: Inventory completeness
**Category:** Inventory
**Severity:** High
**How to verify:** Collect hostname (`hostname -f`), IPv4 addresses (`hostname -I` or `ip -4 addr`), OS name (`hostnamectl`), and hardware UUID (`dmidecode -s system-uuid` when permitted). Record location/owner from INVENTORY.md.
**Pass criteria:** Hostname, OS version, and at least one non-loopback IPv4 address are recorded in evidence.

---

## REQ-002: Operating system version
**Category:** Operating System
**Severity:** High
**How to verify:** Collect `/etc/os-release`, `hostnamectl`, and `uname -r`.
**Pass criteria:** Operating system version, distribution, and kernel version are identified and supported.

---

## REQ-003: Disk SMART status
**Category:** Storage
**Severity:** Medium
**How to verify:** Execute `smartctl -H` for every physical disk where available.
**Pass criteria:** SMART overall health reports PASSED.

---

## REQ-004: Running services
**Category:** Services
**Severity:** High
**How to verify:** Execute `systemctl list-units --type=service --state=running`.
**Pass criteria:** Running services inventory is collected.

---

## REQ-005: Installed packages
**Category:** Software
**Severity:** Medium
**How to verify:** Execute `rpm -qa` or `dpkg-query -W`.
**Pass criteria:** Installed package inventory is collected.

---

## REQ-006: Listening ports
**Category:** Network
**Severity:** High
**How to verify:** Execute `ss -tulpen` (or `netstat -tulpen` where needed) and capture listening TCP/UDP ports with bound addresses.
**Pass criteria:** Listening ports inventory is collected with process ownership details.

---
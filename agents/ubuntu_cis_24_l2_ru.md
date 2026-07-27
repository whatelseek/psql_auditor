---
id: ubuntu_cis_24_l2_ru
aliases: [ubuntu, ubuntu24, ubuntu-cis, ubuntu-cis-24, cis-ubuntu-24, ubuntu l2, ubuntu cis]
description: CIS Ubuntu Linux 24.04 LTS v1.0.0 Level 2 Server (simplified checklist)
domain: cybersecurity
language: ru
family_id: ubuntu_cis_24_l2
type: audit
title: CIS Ubuntu 24.04 L2
detect:
  os_ids: [ubuntu]
version: "24.0"
applicability:
  all:
    - fact: os.family
      operator: equals
      value: linux
  any:
    - fact: os.distribution
      operator: in
      value: [ubuntu]
    - fact: technology.ubuntu.status
      operator: in
      value: [confirmed, suspected]
    - fact: technology.linux.status
      operator: in
      value: [confirmed, suspected]
required_capabilities:
  any_of:
    - ssh.command.read
required_facts:
  - os.family
discovery_hints:
  - capability: ssh.command.read
    purpose: Confirm Linux/Ubuntu OS identity
    operation_ids: [read_os_release]
    expected_facts: [os.family, os.distribution, os.version]
---
# CIS Ubuntu Linux 24.04 LTS v1.0.0 (Level 2 Server, RU)

Краткий operational-чеклист для SSH-проверок (RU-вариант фреймворка).
Используйте сфокусированные проверки и фиксируйте только подтвержденные данные.

## REQ-001: 1.1.1.6 Ensure overlayfs kernel module is not available
**Category:** Initial Setup
**Severity:** High
**How to verify:** Check module state via `lsmod`, `modprobe --showconfig`, and test-load behavior for `overlayfs`.
**Pass criteria:** `overlayfs` is not loaded, is blacklisted, and cannot be loaded.

---

## REQ-002: 1.1.1.7 Ensure squashfs kernel module is not available
**Category:** Initial Setup
**Severity:** High
**How to verify:** Check module state via `lsmod`, `modprobe --showconfig`, and test-load behavior for `squashfs`.
**Pass criteria:** `squashfs` is not loaded, is blacklisted, and cannot be loaded.

---

## REQ-003: 1.1.1.8 Ensure udf kernel module is not available
**Category:** Initial Setup
**Severity:** High
**How to verify:** Check module state via `lsmod`, `modprobe --showconfig`, and test-load behavior for `udf`.
**Pass criteria:** `udf` is not loaded, is blacklisted, and cannot be loaded.

---

## REQ-004: 1.1.2.3.1 Ensure separate partition exists for /home
**Category:** Initial Setup
**Severity:** High
**How to verify:** Inspect `/proc/self/mountinfo` (or `findmnt`) for a dedicated `/home` mount.
**Pass criteria:** `/home` is mounted as a separate filesystem.

---

## REQ-005: 1.1.2.4.1 Ensure separate partition exists for /var
**Category:** Initial Setup
**Severity:** High
**How to verify:** Inspect `/proc/self/mountinfo` (or `findmnt`) for a dedicated `/var` mount.
**Pass criteria:** `/var` is mounted as a separate filesystem.

---

## REQ-006: 1.1.2.5.1 Ensure separate partition exists for /var/tmp
**Category:** Initial Setup
**Severity:** High
**How to verify:** Inspect `/proc/self/mountinfo` (or `findmnt`) for a dedicated `/var/tmp` mount.
**Pass criteria:** `/var/tmp` is mounted as a separate filesystem.

---

## REQ-007: 1.1.2.6.1 Ensure separate partition exists for /var/log
**Category:** Initial Setup
**Severity:** High
**How to verify:** Inspect `/proc/self/mountinfo` (or `findmnt`) for a dedicated `/var/log` mount.
**Pass criteria:** `/var/log` is mounted as a separate filesystem.

---

## REQ-008: 1.1.2.7.1 Ensure separate partition exists for /var/log/audit
**Category:** Initial Setup
**Severity:** High
**How to verify:** Inspect `/proc/self/mountinfo` (or `findmnt`) for a dedicated `/var/log/audit` mount.
**Pass criteria:** `/var/log/audit` is mounted as a separate filesystem.

---

## REQ-009: 1.3.1.4 Ensure all AppArmor Profiles are enforcing
**Category:** Initial Setup
**Severity:** High
**How to verify:** Run `apparmor_status` and review loaded profile modes.
**Pass criteria:** All loaded AppArmor profiles are in enforce mode.

---

## REQ-010: 1.7.1 Ensure GDM is removed
**Category:** Initial Setup
**Severity:** High
**How to verify:** Check package status with `dpkg -s gdm3`.
**Pass criteria:** `gdm3` is not installed.

---

## REQ-011: 2.1.20 Ensure X window server services are not in use
**Category:** Services
**Severity:** High
**How to verify:** Check package status with `dpkg -s xserver-common`.
**Pass criteria:** `xserver-common` is not installed.

---

## REQ-012: 3.2.1 Ensure dccp kernel module is not available
**Category:** Network
**Severity:** High
**How to verify:** Check module state via `lsmod`, `modprobe --showconfig`, and test-load behavior for `dccp`.
**Pass criteria:** `dccp` is not loaded, is blacklisted, and cannot be loaded.

---

## REQ-013: 3.2.2 Ensure tipc kernel module is not available
**Category:** Network
**Severity:** High
**How to verify:** Check module state via `lsmod`, `modprobe --showconfig`, and test-load behavior for `tipc`.
**Pass criteria:** `tipc` is not loaded, is blacklisted, and cannot be loaded.

---

## REQ-014: 3.2.3 Ensure rds kernel module is not available
**Category:** Network
**Severity:** High
**How to verify:** Check module state via `lsmod`, `modprobe --showconfig`, and test-load behavior for `rds`.
**Pass criteria:** `rds` is not loaded, is blacklisted, and cannot be loaded.

---

## REQ-015: 3.2.4 Ensure sctp kernel module is not available
**Category:** Network
**Severity:** High
**How to verify:** Check module state via `lsmod`, `modprobe --showconfig`, and test-load behavior for `sctp`.
**Pass criteria:** `sctp` is not loaded, is blacklisted, and cannot be loaded.

---

## REQ-016: 5.1.8 Ensure sshd DisableForwarding is enabled
**Category:** Access Authentication Authorization
**Severity:** High
**How to verify:** Evaluate effective SSH settings with `sshd -T` (and host/user/port contexts if needed).
**Pass criteria:** Effective SSH configuration sets `DisableForwarding yes`.

---

## REQ-017: 5.1.9 Ensure sshd GSSAPIAuthentication is disabled
**Category:** Access Authentication Authorization
**Severity:** High
**How to verify:** Evaluate effective SSH settings with `sshd -T` (and host/user/port contexts if needed).
**Pass criteria:** Effective SSH configuration sets `GSSAPIAuthentication no`.

---

## REQ-018: 5.2.4 Ensure users must provide password for privilege escalation
**Category:** Access Authentication Authorization
**Severity:** High
**How to verify:** Review `/etc/sudoers` and `/etc/sudoers.d/*` for active `NOPASSWD` rules.
**Pass criteria:** No active `NOPASSWD` entries exist unless approved and documented by customer policy.

---
---
id: ubuntu_cis_24_l2_ru
aliases: [ubuntu, ubuntu24, ubuntu-cis, ubuntu-cis-24, cis-ubuntu-24, ubuntu l2, ubuntu cis, ubuntu ru, ubuntu русский]
description: CIS Ubuntu Linux 24.04 LTS v1.0.0 Level 2 Server (RU variant)
domain: cybersecurity
language: ru
family_id: ubuntu_cis_24_l2
detect:
  os_ids: [ubuntu]
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

## REQ-019: 5.3.3.1.3 Ensure password failed attempts lockout includes root account
**Category:** Access Authentication Authorization
**Severity:** High
**How to verify:** Review `faillock` and PAM configuration (`/etc/security/faillock.conf`, relevant PAM profile files).
**Pass criteria:** Root account lockout controls are enabled and comply with policy (including `even_deny_root` behavior).

---

## REQ-020: 5.4.1.2 Ensure minimum password days is configured
**Category:** Access Authentication Authorization
**Severity:** High
**How to verify:** Check `PASS_MIN_DAYS` in `/etc/login.defs` and per-user minimum days in `/etc/shadow`.
**Pass criteria:** Password minimum days is greater than zero per policy and no applicable user violates the minimum.

---

## REQ-021: 5.4.3.1 Ensure nologin is not listed in /etc/shells
**Category:** Access Authentication Authorization
**Severity:** High
**How to verify:** Inspect `/etc/shells`.
**Pass criteria:** `nologin` is not listed as a valid login shell in `/etc/shells`.

---

## REQ-022: 6.2.1.1 Ensure auditd packages are installed
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Check package status for `auditd` and `audispd-plugins`.
**Pass criteria:** `auditd` and `audispd-plugins` are installed.

---

## REQ-023: 6.2.1.2 Ensure auditd service is enabled and active
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Run `systemctl is-enabled auditd` and `systemctl is-active auditd`.
**Pass criteria:** `auditd` is enabled and currently active.

---

## REQ-024: 6.2.1.3 Ensure auditing for processes that start prior to auditd is enabled
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Inspect kernel boot parameters in grub configuration.
**Pass criteria:** Active boot entries include `audit=1`.

---

## REQ-025: 6.2.1.4 Ensure audit_backlog_limit is sufficient
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Inspect kernel boot parameters in grub configuration.
**Pass criteria:** Active boot entries define `audit_backlog_limit` at or above policy minimum (CIS baseline: 8192+).

---

## REQ-026: 6.2.2.1 Ensure audit log storage size is configured
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Inspect `/etc/audit/auditd.conf` for `max_log_file`.
**Pass criteria:** `max_log_file` is explicitly configured to an approved value.

---

## REQ-027: 6.2.2.2 Ensure audit logs are not automatically deleted
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Inspect `/etc/audit/auditd.conf` for `max_log_file_action`.
**Pass criteria:** `max_log_file_action` is set to `keep_logs`.

---

## REQ-028: 6.2.2.3 Ensure system is disabled when audit logs are full
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Inspect `/etc/audit/auditd.conf` for `disk_full_action` and `disk_error_action`.
**Pass criteria:** `disk_full_action` and `disk_error_action` use restrictive values required by policy (typically `single` or `halt`).

---

## REQ-029: 6.2.2.4 Ensure system warns when audit logs are low on space
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** Inspect `/etc/audit/auditd.conf` for `space_left_action` and `admin_space_left_action`.
**Pass criteria:** Low-space actions are configured according to policy (warning/escalation and administrative threshold action).

---

## REQ-030: 6.2.3.1 Ensure changes to system administration scope (sudoers) is collected
**Category:** Logging and Auditing
**Severity:** High
**How to verify:** List active audit rules (`auditctl -l`) for `/etc/sudoers` and `/etc/sudoers.d`.
**Pass criteria:** Active audit rules monitor write/attribute changes to sudoers scope files with an appropriate key.

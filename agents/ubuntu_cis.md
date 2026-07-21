---
id: ubuntu_cis
aliases: [ubuntu, linux, debian, host, os]
description: Ubuntu CIS host hardening checklist
domain: cybersecurity
detect:
  os_ids: [ubuntu, debian]
---
# Ubuntu CIS Benchmark (scaffold)

Scaffold CIS-style Ubuntu host checklist. Replace or extend for your benchmark version.
Agent verifies via SSH on the target host.

## REQ-001: Password hashing algorithm
**Category:** Authentication
**Severity:** High
**How to verify:** SSH: inspect `/etc/login.defs` (`ENCRYPT_METHOD`) and PAM password settings.
**Pass criteria:** `ENCRYPT_METHOD` is `SHA512` or `YESCRYPT` (not DES/MD5).

## REQ-002: SSH root login disabled
**Category:** Remote Access
**Severity:** Critical
**How to verify:** SSH: read `/etc/ssh/sshd_config` for `PermitRootLogin`.
**Pass criteria:** `PermitRootLogin no` (or `prohibit-password` only if org policy allows keys).

## REQ-003: SSH password authentication
**Category:** Remote Access
**Severity:** High
**How to verify:** SSH: check `PasswordAuthentication` in `sshd_config`.
**Pass criteria:** Password authentication disabled when key-based access is required by policy.

## REQ-004: Unattended upgrades / security patches
**Category:** Patch Management
**Severity:** High
**How to verify:** SSH: `apt list --upgradable` / check `unattended-upgrades` package and config.
**Pass criteria:** Security updates are applied or unattended-upgrades is configured.

## REQ-005: Firewall enabled
**Category:** Network
**Severity:** High
**How to verify:** SSH: `ufw status` or `nft list ruleset` / `iptables -L`.
**Pass criteria:** Host firewall is active with a default-deny or documented allow policy.

## REQ-006: AppArmor enabled
**Category:** Mandatory Access Control
**Severity:** Medium
**How to verify:** SSH: `aa-status` or check `apparmor` service / `/sys/module/apparmor`.
**Pass criteria:** AppArmor is enabled and enforcing for key profiles.

## REQ-007: Unnecessary world-writable directories
**Category:** Filesystem
**Severity:** Medium
**How to verify:** SSH: find world-writable dirs outside expected paths (`/tmp`, `/var/tmp`).
**Pass criteria:** No unexpected sticky/world-writable directories.

## REQ-008: Auditd running
**Category:** Logging & Auditing
**Severity:** Medium
**How to verify:** SSH: `systemctl is-active auditd`; review `/etc/audit/auditd.conf`.
**Pass criteria:** `auditd` is active; audit rules are present for privileged ops.

## REQ-009: Chrony/NTP time sync
**Category:** System Integrity
**Severity:** Low
**How to verify:** SSH: `timedatectl` / chrony/systemd-timesyncd status.
**Pass criteria:** Time synchronization is enabled and synced.

## REQ-010: Sudo logging
**Category:** Privileges
**Severity:** Medium
**How to verify:** SSH: inspect `/etc/sudoers` and `/etc/sudoers.d` for logging / `use_pty`.
**Pass criteria:** Sudo is restricted; commands are logged.

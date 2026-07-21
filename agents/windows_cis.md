---
id: windows_cis
aliases: [windows, win, powershell, server]
description: Windows CIS hardening checklist (SSH/PowerShell)
domain: cybersecurity
detect:
  os_ids: [windows, mswin]
---
# Windows CIS Benchmark (scaffold)

Scaffold CIS-style Windows Server checklist. Verify via SSH with PowerShell
(`pwsh` / `powershell`) when OpenSSH Server is available on the target.

## REQ-001: Password complexity enabled
**Category:** Account Policies
**Severity:** High
**How to verify:** PowerShell: `Get-LocalUser` / `net accounts` / secpol PasswordComplexity.
**Pass criteria:** Password complexity requirements are enabled.

## REQ-002: Account lockout threshold
**Category:** Account Policies
**Severity:** High
**How to verify:** PowerShell/`net accounts` for lockout threshold and duration.
**Pass criteria:** Lockout threshold is set (e.g. ≤ 5) with a non-zero duration.

## REQ-003: Windows Firewall enabled
**Category:** Network
**Severity:** Critical
**How to verify:** PowerShell: `Get-NetFirewallProfile | Select Name,Enabled`.
**Pass criteria:** Domain/Private/Public profiles are enabled (or justified exceptions).

## REQ-004: Remote Desktop NLA
**Category:** Remote Access
**Severity:** High
**How to verify:** PowerShell: RDP NLA registry/setting (`UserAuthentication`).
**Pass criteria:** Network Level Authentication is required for RDP.

## REQ-005: SMBv1 disabled
**Category:** Network Protocols
**Severity:** High
**How to verify:** PowerShell: `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` or registry.
**Pass criteria:** SMBv1 is disabled/removed.

## REQ-006: Windows Update / hotfixes recent
**Category:** Patch Management
**Severity:** High
**How to verify:** PowerShell: `Get-HotFix | Sort InstalledOn -Desc | Select -First 10`.
**Pass criteria:** Recent security updates are installed on a supported build.

## REQ-007: Audit policy privileged use
**Category:** Logging & Auditing
**Severity:** Medium
**How to verify:** `auditpol /get /category:*` or PowerShell audit policy cmdlets.
**Pass criteria:** Privileged use / logon events are audited (success+failure as required).

## REQ-008: Local admin membership
**Category:** Privileges
**Severity:** High
**How to verify:** PowerShell: `Get-LocalGroupMember Administrators`.
**Pass criteria:** Only approved admin accounts; no unnecessary nested groups.

## REQ-009: Defender / antimalware running
**Category:** Malware Protection
**Severity:** High
**How to verify:** PowerShell: `Get-MpComputerStatus` (Defender) or org EDR equivalent.
**Pass criteria:** Real-time protection is enabled and signatures are recent.

## REQ-010: Guest account disabled
**Category:** Accounts
**Severity:** Medium
**How to verify:** PowerShell: `Get-LocalUser Guest | Select Enabled`.
**Pass criteria:** Guest account is disabled.

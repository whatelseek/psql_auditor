---
id: host_facts
aliases: [host facts, host inventory, facts, system inventory, baseline inventory]
description: Host inventory facts — OS, hardware, storage, network, services, software
domain: it
detect:
  always: true
---
# Host Facts Inventory Checklist

Deep host inventory for engagement baselines. Complements CIS checklists.
Prefer SSH tools; do not invent values.

## REQ-001: Inventory completeness
**Category:** Inventory
**Severity:** High
**How to verify:** Collect hostname (`hostname -f`), IPv4 addresses (`hostname -I` or `ip -4 addr`), OS name (`hostnamectl`), and hardware UUID (`dmidecode -s system-uuid` when permitted). Record location/owner from CMDB (NetBox) or INVENTORY.md.
**Pass criteria:** Hostname, OS version, and at least one non-loopback IPv4 address are recorded in evidence.

---

## REQ-002: Operating system version
**Category:** Operating System
**Severity:** High
**How to verify:** Collect `/etc/os-release`, `hostnamectl`, and `uname -r`.
**Pass criteria:** Operating system version, distribution, and kernel version are identified and supported.

---

## REQ-003: System uptime
**Category:** Operating System
**Severity:** Medium
**How to verify:** Execute `uptime` and `who -b`.
**Pass criteria:** System uptime and last boot time are successfully collected.

---

## REQ-004: CPU configuration
**Category:** Hardware
**Severity:** Medium
**How to verify:** Execute `lscpu`.
**Pass criteria:** CPU model, sockets, cores, threads, virtualization support, and NUMA topology are collected.

---

## REQ-005: Memory configuration
**Category:** Hardware
**Severity:** Medium
**How to verify:** Execute `free -h`, `cat /proc/meminfo`.
**Pass criteria:** Total memory, available memory, and swap configuration are recorded.

---

## REQ-006: Disk inventory
**Category:** Storage
**Severity:** High
**How to verify:** Execute `lsblk -f`, `blkid`, `df -hl` (local filesystems only; never bare `df -h`).
**Pass criteria:** Every mounted filesystem, block device, filesystem type, and capacity are documented.

---

## REQ-007: Filesystem utilization
**Category:** Storage
**Severity:** High
**How to verify:** Execute `df -hl` and `df -i`.
**Pass criteria:** No filesystem exceeds the utilization threshold defined by the customer (default 85%) and inode usage is collected.

---

## REQ-008: Mount configuration
**Category:** Storage
**Severity:** Medium
**How to verify:** Execute `findmnt -a` and `mount`.
**Pass criteria:** All mounted filesystems and mount options are collected.

---

## REQ-009: LVM configuration
**Category:** Storage
**Severity:** Medium
**How to verify:** Execute `vgs`, `lvs`, `pvs`.
**Pass criteria:** Volume groups, logical volumes, and free VG capacity are recorded.

---

## REQ-010: RAID health
**Category:** Storage
**Severity:** High
**How to verify:** Execute `cat /proc/mdstat` or vendor RAID utility (`storcli`, `megacli`) when available.
**Pass criteria:** RAID status is healthy with no degraded arrays.

---

## REQ-011: Disk SMART status
**Category:** Storage
**Severity:** Medium
**How to verify:** Execute `smartctl -H` for every physical disk where available.
**Pass criteria:** SMART overall health reports PASSED.

---

## REQ-012: Network interfaces
**Category:** Network
**Severity:** High
**How to verify:** Execute `ip addr`, `ip link`, `ip route`.
**Pass criteria:** Every active interface has operational state, IP address, MTU, and routing information collected.

---

## REQ-013: DNS configuration
**Category:** Network
**Severity:** Medium
**How to verify:** Review `/etc/resolv.conf` and execute `resolvectl status` when systemd-resolved is used.
**Pass criteria:** DNS servers and search domains are documented.

---

## REQ-014: Time synchronization
**Category:** Network
**Severity:** High
**How to verify:** Execute `timedatectl`, `chronyc tracking` or `ntpq -p`.
**Pass criteria:** Time synchronization service is active and synchronized.

---

## REQ-015: Running services
**Category:** Services
**Severity:** High
**How to verify:** Execute `systemctl list-units --type=service --state=running`.
**Pass criteria:** Running services inventory is collected.

---

## REQ-016: Failed services
**Category:** Services
**Severity:** High
**How to verify:** Execute `systemctl --failed`.
**Pass criteria:** No failed services are present or all failures are documented.

---

## REQ-017: Scheduled jobs
**Category:** Services
**Severity:** Medium
**How to verify:** Review `/etc/crontab`, `/etc/cron.*`, user crontabs, and `systemctl list-timers`.
**Pass criteria:** Scheduled jobs and timers are inventoried.

---

## REQ-018: System logs
**Category:** Logging
**Severity:** Medium
**How to verify:** Execute `journalctl -p err -b` and review `dmesg`.
**Pass criteria:** No unresolved kernel or service errors are present, or all findings are documented.

---

## REQ-019: Process health
**Category:** Processes
**Severity:** Medium
**How to verify:** Execute `ps aux`, `top -bn1`.
**Pass criteria:** No zombie processes are present and abnormal resource consumption is documented.

---

## REQ-020: Resource utilization
**Category:** Performance
**Severity:** High
**How to verify:** Execute `vmstat`, `iostat`, `mpstat`.
**Pass criteria:** CPU, memory, and disk utilization metrics are successfully collected.

---

## REQ-021: Kernel parameters
**Category:** Configuration
**Severity:** Medium
**How to verify:** Execute `sysctl -a`.
**Pass criteria:** Kernel parameters are exported for review.

---

## REQ-022: File descriptor limits
**Category:** Configuration
**Severity:** Medium
**How to verify:** Execute `ulimit -n` and review `/etc/security/limits.conf`.
**Pass criteria:** Open file limits are collected.

---

## REQ-023: Installed packages
**Category:** Software
**Severity:** Medium
**How to verify:** Execute `rpm -qa` or `dpkg-query -W`.
**Pass criteria:** Installed package inventory is collected.

---

## REQ-024: Pending updates
**Category:** Software
**Severity:** High
**How to verify:** Execute `dnf check-update`, `yum check-update`, `apt list --upgradable`, or platform equivalent.
**Pass criteria:** Pending operating system updates are identified.

---

## REQ-025: Monitoring agents
**Category:** Monitoring
**Severity:** Medium
**How to verify:** Verify presence of monitoring services (Zabbix Agent, Node Exporter, Datadog Agent, Telegraf, etc.) using `systemctl`.
**Pass criteria:** Installed monitoring agents and their operational state are documented.

---

## REQ-026: Backup agents
**Category:** Backup
**Severity:** Medium
**How to verify:** Verify installed backup agents and related services.
**Pass criteria:** Backup software and service status are documented.

---

## REQ-027: Virtualization integration
**Category:** Virtualization
**Severity:** Low
**How to verify:** Detect virtualization (`systemd-detect-virt`) and verify VMware Tools, Hyper-V Integration Services, or QEMU Guest Agent.
**Pass criteria:** Guest integration tools are identified and their status is collected.

---

## REQ-028: Container runtime
**Category:** Containers
**Severity:** Medium
**How to verify:** Execute `docker info`, `podman info`, or `ctr version` where applicable.
**Pass criteria:** Container runtime version and operational status are collected.

---

## REQ-029: Boot configuration
**Category:** Operating System
**Severity:** Medium
**How to verify:** Execute `efibootmgr` (UEFI), review `/boot`, and collect kernel boot parameters.
**Pass criteria:** Boot mode and current boot configuration are documented.

---

## REQ-030: System limits summary
**Category:** Configuration
**Severity:** Low
**How to verify:** Collect `sysctl`, `limits.conf`, `loginctl show-user`, and `systemd-analyze`.
**Pass criteria:** System configuration baseline is exported for further assessment.

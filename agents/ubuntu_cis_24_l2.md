---
id: ubuntu_cis_24_l2
aliases: [ubuntu, ubuntu24, ubuntu-cis, ubuntu-cis-24, cis-ubuntu-24, ubuntu l2, ubuntu cis]
description: CIS Ubuntu Linux 24.04 LTS v1.0.0 Level 2 Server (converted from Nessus .audit)
domain: cybersecurity
detect:
  os_ids: [ubuntu]
---
# CIS Ubuntu Linux 24.04 LTS v1.0.0 (Level 2 Server)

Converted from CIS WorkBench / Nessus `.audit` for automated SSH verification.
Source benchmark: https://workbench.cisecurity.org/benchmarks/18959.

Notes:
- Many checks need elevated privileges; use an inventory SSH user with sudo where required.
- Composite controls may require several probes; playbook stores the primary `ssh_run` command.
- Overlayfs/squashfs checks can break containers/Snaps — treat fails in context.

## REQ-001: 1.1.1.6 Ensure overlayfs kernel module is not available
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.1.6`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `1.1.1.6` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   a_output=() a_output2=() a_output3=() l_dl="" l_mod_name="overlayfs" l_mod_type="fs"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_chk()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --showconfig | grep -P -- '\b(install|blacklist)\h+'"${l_mod_chk_name//-/_}"'\b')
      if ! lsmod | grep "$l_mod_chk_name" &> /dev/null; then
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** overlayfs is a Linux filesystem that layers multiple filesystems to create a single unified view which allows a user to "merge" several mount points into a unified filesystem.

The overlayfs has known CVE's: CVE-2023-32629, CVE-2023-2640, CVE-2023-0386. Disabling the overlayfs reduces the local attack surface by removing support for unnecessary filesystem types and mitigates potential risks associated with unauthorized execution of setuid files, enhancing the overall system security.
**Remediation (CIS):** Run the following script to unload and disable the overlayfs module:

- IF - the overlayfs kernel module is available in ANY installed kernel:

 - Create a file ending in .conf with install overlayfs /bin/false in the /etc/modprobe.d/ directory
 - Create a file ending in .conf with blacklist overlayfs in the /etc/modprobe.d/ directory
 - Run modprobe -r overlayfs 2>/dev/null; rmmod overlayfs 2>/dev/null to remove overlayfs from the kernel

- IF - the overlayfs kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

#!/usr/bin/env bash

{
   a_output2=() a_output3=() l_dl="" l_mod_name="overlayfs" l_mod_type="fs"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_fix()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-002: 1.1.1.7 Ensure squashfs kernel module is not available
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.1.7`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `1.1.1.7` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_output3="" l_dl="" # clear variables
   unset a_output; unset a_output2 # unset arrays
   l_mod_name="squashfs" # set module name
   l_mod_type="fs" # set module type
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_chk()
   {
      l_dl="y" # Set to ignore duplicate checks
      a_showconfig=() # Create array with modprobe output
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A squashfs image can be used without having to first decompress the image.

Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
**Remediation (CIS):** Run the following script to unload and disable the udf module:

- IF - the squashfs kernel module is available in ANY installed kernel:

 - Create a file ending in .conf with install squashfs /bin/false in the /etc/modprobe.d/ directory
 - Create a file ending in .conf with blacklist squashfs in the /etc/modprobe.d/ directory
 - Run modprobe -r squashfs 2>/dev/null; rmmod squashfs 2>/dev/null to remove squashfs from the kernel

- IF - the squashfs kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

#!/usr/bin/env bash

{
   a_output2=() a_output3=() l_dl="" l_mod_name="squashfs" l_mod_type="fs"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_fix()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --sh…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-003: 1.1.1.8 Ensure udf kernel module is not available
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.1.8`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `1.1.1.8` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   a_output=() a_output2=() a_output3=() l_dl="" l_mod_name="udf" l_mod_type="fs"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_chk()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --showconfig | grep -P -- '\b(install|blacklist)\h+'"${l_mod_chk_name//-/_}"'\b')
      if ! lsmod | grep "$l_mod_chk_name" &> /dev/null; then
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.

Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
**Remediation (CIS):** Run the following script to unload and disable the udf module:

- IF - the udf kernel module is available in ANY installed kernel:

 - Create a file ending in .conf with install udf /bin/false in the /etc/modprobe.d/ directory
 - Create a file ending in .conf with blacklist udf in the /etc/modprobe.d/ directory
 - Run modprobe -r udf 2>/dev/null; rmmod udf 2>/dev/null to remove udf from the kernel

- IF - the udf kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

#!/usr/bin/env bash

{
   a_output2=() a_output3=() l_dl="" l_mod_name="udf" l_mod_type="fs"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_fix()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --showconfig | grep -P -- '\b(install|blackl…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-004: 1.1.2.3.1 Ensure separate partition exists for /home
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.2.3.1`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: inspect `/proc/self/mountinfo` matching regex `[\s]+/home[\s]+`.
- Expect output matching: `[\s]+/home[\s]+`.
**Pass criteria:** [\s]+/home[\s]+
**Background:** The /home directory is used to support disk storage needs of local users.

The default installation only creates a single / partition. Since the /home directory contains user generated data, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to /home and impact all local users.

Configuring /home as its own file system allows an administrator to set additional mount options such as noexec/nosuid/nodev . These options limit an attacker…
**Remediation (CIS):** For new installations, during installation create a custom partition setup and specify a separate partition for /home.

For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.

Impact:

Resizing filesystems is a common activity in cloud-hosted servers. Separate filesystem partitions may prevent successful resizing or may require the installation of additional tools solely for the purpose of resizing operations. The use of these additional tools may introduce their own security considerations.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-005: 1.1.2.4.1 Ensure separate partition exists for /var
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.2.4.1`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: inspect `/proc/self/mountinfo` matching regex `[\s]+/var[\s]+`.
- Expect output matching: `[\s]+/var[\s]+`.
**Pass criteria:** [\s]+/var[\s]+
**Background:** The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.

The reasoning for mounting /var on a separate partition is as follows.

The default installation only creates a single / partition. Since the /var directory may contain world writable files and directories, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system. In addition, other operations on the system could fill up the disk unrelated to /var and cause uninte…
**Remediation (CIS):** For new installations, during installation create a custom partition setup and specify a separate partition for /var.

For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.

Impact:

Resizing filesystems is a common activity in cloud-hosted servers. Separate filesystem partitions may prevent successful resizing or may require the installation of additional tools solely for the purpose of resizing operations. The use of these additional tools may introduce their own security considerations.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-006: 1.1.2.5.1 Ensure separate partition exists for /var/tmp
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.2.5.1`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: inspect `/proc/self/mountinfo` matching regex `[\s]+/var/tmp[\s]+`.
- Expect output matching: `[\s]+/var/tmp[\s]+`.
**Pass criteria:** [\s]+/var/tmp[\s]+
**Background:** The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications. Temporary files residing in /var/tmp are to be preserved between reboots.

The default installation only creates a single / partition. Since the /var/tmp directory is world-writable, there is a risk of resource exhaustion. In addition, other operations on the system could fill up the disk unrelated to /var/tmp and cause potential disruption to daemons as the disk is full.

Configuring /var/tmp as its own file system allows an administrator to set additional mount options such as…
**Remediation (CIS):** For new installations, during installation create a custom partition setup and specify a separate partition for /var/tmp.

For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.

Impact:

Resizing filesystems is a common activity in cloud-hosted servers. Separate filesystem partitions may prevent successful resizing or may require the installation of additional tools solely for the purpose of resizing operations. The use of these additional tools may introduce their own security considerations.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-007: 1.1.2.6.1 Ensure separate partition exists for /var/log
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.2.6.1`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: inspect `/proc/self/mountinfo` matching regex `[\s]+/var/log[\s]+`.
- Expect output matching: `[\s]+/var/log[\s]+`.
**Pass criteria:** [\s]+/var/log[\s]+
**Background:** The /var/log directory is used by system services to store log data.

The default installation only creates a single / partition. Since the /var/log directory contains log files which can grow quite large, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole.

Configuring /var/log as its own file system allows an administrator to set additional mount options such as noexec/nosuid/nodev . These options limit an attackers ability to create exploits on the system. Other options allow for specific behavior. See man m…
**Remediation (CIS):** For new installations, during installation create a custom partition setup and specify a separate partition for /var/log.

For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.

Impact:

Resizing filesystems is a common activity in cloud-hosted servers. Separate filesystem partitions may prevent successful resizing, or may require the installation of additional tools solely for the purpose of resizing operations. The use of these additional tools may introduce their own security considerations.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-008: 1.1.2.7.1 Ensure separate partition exists for /var/log/audit
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.1.2.7.1`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: inspect `/proc/self/mountinfo` matching regex `[\s]+/var/log/audit[\s]+`.
- Expect output matching: `[\s]+/var/log/audit[\s]+`.
**Pass criteria:** [\s]+/var/log/audit[\s]+
**Background:** The auditing daemon, auditd, stores log data in the /var/log/audit directory.

The default installation only creates a single / partition. Since the /var/log/audit directory contains the audit.log file which can grow quite large, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to /var/log/audit and cause auditd to trigger its space_left_action as the disk is full. See man auditd.conf for details.

Configuring /var/log/audit as its…
**Remediation (CIS):** For new installations, during installation create a custom partition setup and specify a separate partition for /var/log/audit.

For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.

Impact:

Resizing filesystems is a common activity in cloud-hosted servers. Separate filesystem partitions may prevent successful resizing or may require the installation of additional tools solely for the purpose of resizing operations. The use of these additional tools may introduce their own security considerations.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-009: 1.3.1.4 Ensure all AppArmor Profiles are enforcing
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.3.1.4`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `1.3.1.4` (3 command(s); prefer playbook `ssh_run`).
```bash
/sbin/apparmor_status
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** AppArmor profiles define what resources applications are able to access.

Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated.
**Remediation (CIS):** Run the following command to set all profiles to enforce mode:

# aa-enforce /etc/apparmor.d/*

Note: Any unconfined processes may need to have a profile created or activated for them and then be restarted
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-010: 1.7.1 Ensure GDM is removed
**Category:** Initial Setup
**Severity:** High
**CIS ID:** `1.7.1`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/bin/dpkg -s gdm3 2>&1 | /bin/grep -E '(^Status:|not installed)'
```
- Expect output matching: `(^Status: deinstall ok|not installed)`.
**Pass criteria:** (^Status: deinstall ok|not installed)
**Background:** The GNOME Display Manager (GDM) is a program that manages graphical display servers and handles graphical user logins.

If a Graphical User Interface (GUI) is not required, it should be removed to reduce the attack surface of the system.
**Remediation (CIS):** Run the following commands to uninstall gdm3 and remove unused dependencies:

# apt purge gdm3
# apt autoremove gdm3

Impact:

Removing the GNOME Display manager will remove the Graphical User Interface (GUI) from the system.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-011: 2.1.20 Ensure X window server services are not in use
**Category:** Services
**Severity:** High
**CIS ID:** `2.1.20`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/bin/dpkg -s xserver-common 2>&1 | /bin/grep -E '(^Status:|not installed)'
```
- Expect output matching: `(^Status: deinstall ok|not installed)`.
**Pass criteria:** (^Status: deinstall ok|not installed)
**Background:** The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.

Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface.
**Remediation (CIS):** - IF - a Graphical Desktop Manager or X-Windows server is not required and approved by local site policy:

Run the following command to remove the X Windows Server package:

# apt purge xserver-common

Impact:

If a Graphical Desktop Manager (GDM) is in use on the system, there may be a dependency on the xorg-x11-server-common package. If the GDM is required and approved by local site policy, the package should not be removed.

Many Linux systems run applications which require a Java runtime. Some Linux Java packages have a dependency on specific X Windows xorg-x11-fonts. One workaround to avoid this dependency is to use the "headless" Java packages for your specific Java runtime.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-012: 3.2.1 Ensure dccp kernel module is not available
**Category:** Network
**Severity:** High
**CIS ID:** `3.2.1`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `3.2.1` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_output3="" l_dl="" # clear variables
   unset a_output; unset a_output2 # unset arrays
   l_mod_name="dccp" # set module name
   l_mod_type="net" # set module type
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_chk()
   {
      l_dl="y" # Set to ignore duplicate checks
      a_showconfig=() # Create array with modprobe output
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery.

- IF - the protocol is not required, it is recommended that the drivers not be installed to reduce the potential attack surface.
**Remediation (CIS):** Run the following script to unload and disable the dccp module:

- IF - the dccp kernel module is available in ANY installed kernel:

 - Create a file ending in .conf with install dccp /bin/false in the /etc/modprobe.d/ directory
 - Create a file ending in .conf with blacklist dccp in the /etc/modprobe.d/ directory
 - Run modprobe -r dccp 2>/dev/null; rmmod dccp 2>/dev/null to remove dccp from the kernel

- IF - the dccp kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

#!/usr/bin/env bash

{
   a_output2=() a_output3=() l_dl="" l_mod_name="dccp" l_mod_type="net"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_fix()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --showconfig | grep -P -- '\b(inst…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-013: 3.2.2 Ensure tipc kernel module is not available
**Category:** Network
**Severity:** High
**CIS ID:** `3.2.2`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `3.2.2` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_output3="" l_dl="" # clear variables
   unset a_output; unset a_output2 # unset arrays
   l_mod_name="tipc" # set module name
   l_mod_type="net" # set module type
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_chk()
   {
      l_dl="y" # Set to ignore duplicate checks
      a_showconfig=() # Create array with modprobe output
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes.

- IF - the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
**Remediation (CIS):** Run the following script to unload and disable the tipc module:

- IF - the tipc kernel module is available in ANY installed kernel:

 - Create a file ending in .conf with install tipc /bin/false in the /etc/modprobe.d/ directory
 - Create a file ending in .conf with blacklist tipc in the /etc/modprobe.d/ directory
 - Run modprobe -r tipc 2>/dev/null; rmmod tipc 2>/dev/null to remove tipc from the kernel

- IF - the tipc kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

#!/usr/bin/env bash

{
   a_output2=() a_output3=() l_dl="" l_mod_name="tipc" l_mod_type="net"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_fix()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --showconfig | grep -P -- '\b(inst…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-014: 3.2.3 Ensure rds kernel module is not available
**Category:** Network
**Severity:** High
**CIS ID:** `3.2.3`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `3.2.3` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_output3="" l_dl="" # clear variables
   unset a_output; unset a_output2 # unset arrays
   l_mod_name="rds" # set module name
   l_mod_type="net" # set module type
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_chk()
   {
      l_dl="y" # Set to ignore duplicate checks
      a_showconfig=() # Create array with modprobe output
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation.

- IF - the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
**Remediation (CIS):** Run the following script to unload and disable the rds module:

- IF - the rds kernel module is available in ANY installed kernel:

 - Create a file ending in .conf with install rds /bin/false in the /etc/modprobe.d/ directory
 - Create a file ending in .conf with blacklist rds in the /etc/modprobe.d/ directory
 - Run modprobe -r rds 2>/dev/null; rmmod rds 2>/dev/null to remove rds from the kernel

- IF - the rds kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

#!/usr/bin/env bash

{
   a_output2=() a_output3=() l_dl="" l_mod_name="rds" l_mod_type="net"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_fix()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --showconfig | grep -P -- '\b(install|black…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-015: 3.2.4 Ensure sctp kernel module is not available
**Category:** Network
**Severity:** High
**CIS ID:** `3.2.4`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `3.2.4` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_output3="" l_dl="" # clear variables
   unset a_output; unset a_output2 # unset arrays
   l_mod_name="sctp" # set module name
   l_mod_type="net" # set module type
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_chk()
   {
      l_dl="y" # Set to ignore duplicate checks
      a_showconfig=() # Create array with modprobe output
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.

- IF - the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
**Remediation (CIS):** Run the following script to unload and disable the sctp module:

- IF - the sctp kernel module is available in ANY installed kernel:

 - Create a file ending in .conf with install sctp /bin/false in the /etc/modprobe.d/ directory
 - Create a file ending in .conf with blacklist sctp in the /etc/modprobe.d/ directory
 - Run modprobe -r sctp 2>/dev/null; rmmod sctp 2>/dev/null to remove sctp from the kernel

- IF - the sctp kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

#!/usr/bin/env bash

{
   a_output2=() a_output3=() l_dl="" l_mod_name="sctp" l_mod_type="net"
   l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"
   f_module_fix()
   {
      l_dl="y" a_showconfig=()
      while IFS= read -r l_showconfig; do
         a_showconfig+=("$l_showconfig")
      done < <(modprobe --showconfig | grep -P -- '\b(inst…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-016: 5.1.8 Ensure sshd DisableForwarding is enabled
**Category:** Access Authentication Authorization
**Severity:** High
**CIS ID:** `5.1.8`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `5.1.8` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash
  {
  ports=$(/bin/grep -s -P "^(Port|Match)" /etc/ssh/sshd_config /etc/sshd_config.d/*.conf | /bin/grep -P -o "(Port|LocalPort)[\s]+[\d]+" | /bin/awk '{print $2}; END {if (NR == 0) print "22"}' | /bin/uniq); for port in ${ports[@]}; do /sbin/sshd -T -C user=root -C host="$(hostname)" -C addr="$(/bin/grep $(hostname) /etc/hosts | /bin/awk '{print $1}')" -C lport=$port | echo "port $port: $(/bin/grep -i ^disableforwarding)"; done | /bin/awk 'BEGIN {f=0} /disableforwarding/i { if ($NF == "no") f++; print $0} END {if (NR == 0) print "Fail: no results returned"; else if (f > 0) print "Fail"; else print "Pass" }'
  }
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The DisableForwarding parameter disables all forwarding features, including X11, ssh-agent(1), TCP and StreamLocal. This option overrides all other forwarding-related options and may simplify restricted configurations.

 - X11Forwarding provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections.
 - ssh-agent is a program to hold private keys used for public key authentication. Through use of environment variables the agent can be located and automatically used for authentication when logging in to other machines using ssh.
 - SSH port forwarding is…
**Remediation (CIS):** Edit the /etc/ssh/sshd_config file to set the DisableForwarding parameter to yes above any Include entry as follows:

DisableForwarding yes

Note: First occurrence of a option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.

Impact:

SSH tunnels are widely used in many corporate environments. In some environments the applications themselves may have very limited native support for security. By utilizing tunneling, compliance with SOX, HIPAA, PCI-DSS, and other standards can be achieved without having to modify the applications.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-017: 5.1.9 Ensure sshd GSSAPIAuthentication is disabled
**Category:** Access Authentication Authorization
**Severity:** High
**CIS ID:** `5.1.9`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `5.1.9` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash
  {
  ports=$(/bin/grep -s -P "^(Port|Match)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | /bin/grep -P -o "(Port|LocalPort)[\s]+[\d]+" | /bin/awk '{print $2}; END {if (NR == 0) print "22"}' | /bin/uniq); for port in ${ports[@]}; do /sbin/sshd -T -C user=root -C host="$(hostname)" -C addr="$(/bin/grep $(hostname) /etc/hosts | /bin/awk '{print $1}')" -C lport=$port | echo "port $port: $(/bin/grep -i ^GSSAPIAuthentication)"; done | /bin/awk 'BEGIN {f=0} /GSSAPIAuthentication/i { if ($NF != "no") f++; print $0} END {if (NR == 0) print "Fail: no results returned"; else if (f > 0) print "Fail"; else print "Pass" }'
  }
# …
```
- Expect output matching: `^Pass$`.
**Pass criteria:** ^Pass$
**Background:** The GSSAPIAuthentication parameter specifies whether user authentication based on GSSAPI is allowed

Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, and should be disabled to reduce the attack surface of the system
**Remediation (CIS):** Edit the /etc/ssh/sshd_config file to set the GSSAPIAuthentication parameter to no above any Include and Match entries as follows:

GSSAPIAuthentication no

Note: First occurrence of an option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-018: 5.2.4 Ensure users must provide password for privilege escalation
**Category:** Access Authentication Authorization
**Severity:** High
**CIS ID:** `5.2.4`
**How to verify:** - Check type: `FILE_CONTENT_CHECK_NOT`.
- SSH: inspect `/etc/sudoers /etc/sudoers.d/*` matching regex `^[^#]*NOPASSWD`.
- Expect output matching: `^[^#]*NOPASSWD`.
**Pass criteria:** ^[^#]*NOPASSWD
**Background:** The operating system must be configured so that users must provide a password for privilege escalation.

Without (re-)authentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user (re-)authenticate.
**Remediation (CIS):** Based on the outcome of the audit procedure, use visudo -f <PATH TO FILE> to edit the relevant sudoers file.

Remove any line with occurrences of NOPASSWD tags in the file.

Impact:

This will prevent automated processes from being able to elevate privileges.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-019: 5.3.3.1.3 Ensure password failed attempts lockout includes root account
**Category:** Access Authentication Authorization
**Severity:** High
**CIS ID:** `5.3.3.1.3`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: verify manually per CIS recommendation.
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** even_deny_root - Root account can become locked as well as regular accounts

root_unlock_time=n - This option implies even_deny_root option. Allow access after n seconds to root account after the account is locked. In case the option is not specified the value is the same as of the unlock_time option.

Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
**Remediation (CIS):** Edit /etc/security/faillock.conf :

 - Remove or update any line containing root_unlock_time, - OR - set it to a value of 60 or more
 - Update or add the following line:

even_deny_root

Run the following command:

# grep -Pl -- '\bpam_faillock\.so\h+([^#\n\r]+\h+)?(even_deny_root|root_unlock_time)' /usr/share/pam-configs/*

Edit any returned files and remove the even_deny_root and root_unlock_time arguments from the pam_faillock.so line(s):

Impact:

Use of unlock_time=0 or root_unlock_time=0 may allow an attacker to cause denial of service to legitimate users.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-020: 5.4.1.2 Ensure minimum password days is configured
**Category:** Access Authentication Authorization
**Severity:** High
**CIS ID:** `5.4.1.2`
**How to verify:** - Check type: `CMD_EXEC+FILE_CONTENT_CHECK`.
SSH run:
```bash
/bin/awk -F: '($2~/^\$.+\$/) {if($4 < @PASSWORD_MIN_DAYS@)print "User: " $1 " PASS_MIN_DAYS: " $4}' /etc/shadow | /bin/awk '{print} END {if (NR == 0) print "pass"; else print "fail"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** PASS_MIN_DAYS < N > - The minimum number of days allowed between password changes. Any password changes attempted sooner than this will be rejected. If not specified, 0 will be assumed (which disables the restriction).

Users may have favorite passwords that they like to use because they are easy to remember and they believe that their password choice is secure from compromise. Unfortunately, passwords are compromised and if an attacker is targeting a specific individual user account, with foreknowledge of data about that user, reuse of old, potentially compromised passwords, may cause a secu…
**Remediation (CIS):** Edit /etc/login.defs and set PASS_MIN_DAYS to a value greater than 0 that follows local site policy:

Example:

PASS_MIN_DAYS 1

Run the following command to modify user parameters for all users with a password set to a minimum days greater than zero that follows local site policy:

# chage --mindays <N> <user>

Example:

# awk -F: '($2~/^\$.+\$/) {if($4 < 1)system ("chage --mindays 1 " $1)}' /etc/shadow

Impact:

If a users password is set by other personnel as a procedure in dealing with a lost or expired password, the user should be forced to update this "set" password with their own password. e.g. force "change at next logon".

If it is not possible to have a user set their own password immediately, and this recommendation or local site procedure may cause a user to continue using a third party generated password, PASS_MIN_DAYS for the effected user should be temporally changed to 0…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-021: 5.4.3.1 Ensure nologin is not listed in /etc/shells
**Category:** Access Authentication Authorization
**Severity:** High
**CIS ID:** `5.4.3.1`
**How to verify:** - Check type: `FILE_CONTENT_CHECK_NOT`.
- SSH: inspect `/etc/shells` matching regex `^\h*([^#\n\r]+)?\/nologin\b`.
- Expect output matching: `^\h*([^#\n\r]+)?\/nologin\b`.
**Pass criteria:** ^\h*([^#\n\r]+)?\/nologin\b
**Background:** /etc/shells is a text file which contains the full pathnames of valid login shells. This file is consulted by chsh and available to be queried by other programs.

Be aware that there are programs which consult this file to find out if a user is a normal user; for example, FTP daemons traditionally disallow access to users with shells not included in this file.

A user can use chsh to change their configured shell.

If a user has a shell configured that isn't in in /etc/shells, then the system assumes that they're somehow restricted. In the case of chsh it means that the user cannot change tha…
**Remediation (CIS):** Edit /etc/shells and remove any lines that include nologin
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-022: 6.2.1.1 Ensure auditd packages are installed
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.1.1`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.1.1` (2 command(s); prefer playbook `ssh_run`).
```bash
/bin/dpkg -s auditd 2>&1 | /bin/grep -E '(^Status:|not installed)'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** auditd is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk

The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
**Remediation (CIS):** Run the following command to Install auditd and audispd-plugins

# apt install auditd audispd-plugins
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-023: 6.2.1.2 Ensure auditd service is enabled and active
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.1.2`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.1.2` (2 command(s); prefer playbook `ssh_run`).
```bash
/bin/systemctl is-active auditd
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Turn on the auditd daemon to record system events.

The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
**Remediation (CIS):** Run the following commands to unmask, enable and start auditd :

# systemctl unmask auditd
# systemctl enable auditd
# systemctl start auditd
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-024: 6.2.1.3 Ensure auditing for processes that start prior to auditd is enabled
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.1.3`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/bin/find /boot -type f -name 'grub.cfg' -exec /bin/grep -Ph -- '^\h*linux' {} + | /bin/grep -v 'audit=1' | /bin/awk '{ print } END { if (NR==0) print "pass" }'
```
- Expect output matching: `^pass$`.
**Pass criteria:** ^pass$
**Background:** Configure grub2 so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.

Audit events need to be captured on processes that start up prior to auditd, so that potential malicious activity cannot go undetected.
**Remediation (CIS):** Edit /etc/default/grub and add audit=1 to GRUB_CMDLINE_LINUX :

Example:

GRUB_CMDLINE_LINUX="audit=1"

Run the following command to update the grub2 configuration:

# update-grub
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-025: 6.2.1.4 Ensure audit_backlog_limit is sufficient
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.1.4`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/bin/find /boot -type f -name 'grub.cfg' -exec /bin/grep -Ph -- '^\h*linux' {} + | /bin/grep -Pv 'audit_backlog_limit=\d+\b' | /bin/awk '{print} END { if (NR==0) print "pass" }'
```
- Expect output matching: `^pass$`.
**Pass criteria:** ^pass$
**Background:** In the kernel-level audit subsystem, a socket buffer queue is used to hold audit events. Whenever a new audit event is received, it is logged and prepared to be added to this queue.

The kernel boot parameter audit_backlog_limit=N, with N representing the amount of messages, will ensure that a queue cannot grow beyond a certain size. If an audit event is logged which would grow the queue beyond this limit, then a failure occurs and is handled according to the system configuration

If an audit event is logged which would grow the queue beyond the audit_backlog_limit, then a failure occurs, aud…
**Remediation (CIS):** Edit /etc/default/grub and add audit_backlog_limit=N to GRUB_CMDLINE_LINUX. The recommended size for N is 8192 or larger.

Example:

GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"

Run the following command to update the grub2 configuration:

# update-grub
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-026: 6.2.2.1 Ensure audit log storage size is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.2.1`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: inspect `/etc/audit/auditd.conf` matching regex `^[\s]*max_log_file[\s]*=`.
- Expect output matching: `^[\s]*max_log_file[\s]*=[\s]*@MAX_AUDIT_LOG_FILE_SIZE@[\s]*$`.
**Pass criteria:** ^[\s]*max_log_file[\s]*=[\s]*@MAX_AUDIT_LOG_FILE_SIZE@[\s]*$
**Background:** Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.

It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost.
**Remediation (CIS):** Set the following parameter in /etc/audit/auditd.conf in accordance with site policy:

max_log_file = <MB>
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-027: 6.2.2.2 Ensure audit logs are not automatically deleted
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.2.2`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: inspect `/etc/audit/auditd.conf` matching regex `^[\s]*max_log_file_action[\s]*=`.
- Expect output matching: `^[\s]*max_log_file_action[\s]*=[\s]*(?i)keep_logs(?-i)[\s]*$`.
**Pass criteria:** ^[\s]*max_log_file_action[\s]*=[\s]*(?i)keep_logs(?-i)[\s]*$
**Background:** The max_log_file_action setting determines how to handle the audit log file reaching the max file size. A value of keep_logs will rotate the logs but never delete old logs.

In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history.
**Remediation (CIS):** Set the following parameter in /etc/audit/auditd.conf:

max_log_file_action = keep_logs
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-028: 6.2.2.3 Ensure system is disabled when audit logs are full
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.2.3`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: verify manually per CIS recommendation.
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** The auditd daemon can be configured to halt the system or put the system in single user mode, if no free space is available or an error is detected on the partition that holds the audit log files.

The disk_full_action parameter tells the system what action to take when no free space is available on the partition that holds the audit log files. Valid values are ignore, syslog, rotate, exec, suspend, single, and halt.

 - ignore, the audit daemon will issue a syslog message but no other action is taken
 - syslog, the audit daemon will issue a warning to syslog
 - rotate, the audit daemon will…
**Remediation (CIS):** Set one of the following parameters in /etc/audit/auditd.conf depending on your local security policies.

disk_full_action = <halt|single>
disk_error_action = <syslog|single|halt>

Example:

disk_full_action = halt
disk_error_action = halt

Impact:

disk_full_action parameter:

 - Set to halt - the auditd daemon will shutdown the system when the disk partition containing the audit logs becomes full.
 - Set to single - the auditd daemon will put the computer system in single user mode when the disk partition containing the audit logs becomes full.

disk_error_action parameter:

 - Set to halt - the auditd daemon will shutdown the system when an error is detected on the partition that holds the audit log files.
 - Set to single - the auditd daemon will put the computer system in single user mode when an error is detected on the partition that holds the audit log files.
 - Set to syslog -…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-029: 6.2.2.4 Ensure system warns when audit logs are low on space
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.2.4`
**How to verify:** - Check type: `FILE_CONTENT_CHECK`.
- SSH: verify manually per CIS recommendation.
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** The auditd daemon can be configured to halt the system, put the system in single user mode or send a warning message, if the partition that holds the audit log files is low on space.

The space_left_action parameter tells the system what action to take when the system has detected that it is starting to get low on disk space. Valid values are ignore, syslog, rotate, email, exec, suspend, single, and halt.

 - ignore, the audit daemon does nothing
 - syslog, the audit daemon will issue a warning to syslog
 - rotate, the audit daemon will rotate logs, losing the oldest to free up space
 - email…
**Remediation (CIS):** Set the space_left_action parameter in /etc/audit/auditd.conf to email, exec, single, or halt :

Example:

space_left_action = email

Set the admin_space_left_action parameter in /etc/audit/auditd.conf to single or halt :

Example:

admin_space_left_action = single

Note: A Mail Transfer Agent (MTA) must be installed and configured properly to set space_left_action = email

Impact:

If the admin_space_left_action is set to single the audit daemon will put the computer system in single user mode.
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-030: 6.2.3.1 Ensure changes to system administration scope (sudoers) is collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.1`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.1` (4 command(s); prefer playbook `ssh_run`).
```bash
/sbin/auditctl -l | /bin/awk '/^ *-w/ &&/\/etc\/sudoers/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor scope changes for system administrators. If the system has been properly configured to force system administrators to log in as themselves first and then use the sudo command to execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers, or files in /etc/sudoers.d, will be written to when the file(s) or related attributes have changed. The audit records will be tagged with the identifier "scope".

Changes in the /etc/sudoers and /etc/sudoers.d files can indicate that an unauthorized change has been made to the scope of system administrator activity.
**Remediation (CIS):** Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor scope changes for system administrators.

Example:

# printf "
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
" >> /etc/audit/rules.d/50-scope.rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

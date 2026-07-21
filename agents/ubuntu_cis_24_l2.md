---
id: ubuntu_cis_24_l2
aliases: [ubuntu24, ubuntu-cis-24, cis-ubuntu-24, ubuntu l2]
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

## REQ-031: 6.2.3.10 Ensure successful file system mounts are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.10`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.10` (5 command(s); prefer playbook `ssh_run`).
```bash
/bin/uname -a | /bin/grep x86_64 | /bin/awk '{print} END {if (NR > 0) print "found"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor the use of the mount system call. The mount (and umount ) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user

It is highly unusual for a non privileged user to mount file systems to the system. While tracking mount commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exp…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor successful file system mounts.

Example:

# {
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
" >> /etc/audit/rules.d/50-mounts.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-032: 6.2.3.11 Ensure session initiation information is collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.11`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.11` (6 command(s); prefer playbook `ssh_run`).
```bash
/sbin/auditctl -l | /bin/awk '/^ *-w/  &&/\/var\/run\/utmp/ &&/ +-p *wa/  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor session initiation events. The parameters in this section track changes to the files associated with session events.

 - /var/run/utmp - tracks all currently logged in users.
 - /var/log/wtmp - file tracks logins, logouts, shutdown, and reboot events.
 - /var/log/btmp - keeps track of failed login attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp.

All audit records will be tagged with the identifier "session."

Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activit…
**Remediation (CIS):** Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor session initiation information.

Example:

# printf "
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
" >> /etc/audit/rules.d/50-session.rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-033: 6.2.3.12 Ensure login and logout events are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.12`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.12` (4 command(s); prefer playbook `ssh_run`).
```bash
/bin/awk '/^ *-w/ && /\/var\/run\/faillock/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor login and logout events. The parameters below track changes to files associated with login/logout events.

 - /var/log/lastlog - maintain records of the last time a user successfully logged in.
 - /var/run/faillock - directory maintains records of login failures via the pam_faillock module.

Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins.
**Remediation (CIS):** Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor login and logout events.

Example:

# printf "
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
" >> /etc/audit/rules.d/50-login.rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-034: 6.2.3.13 Ensure file deletion events by users are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.13`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.13` (5 command(s); prefer playbook `ssh_run`).
```bash
/bin/uname -a | /bin/grep x86_64 | /bin/awk '{print} END {if (NR > 0) print "found"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for:

 - unlink - remove a file
 - unlinkat - remove a file attribute
 - rename - rename a file
 - renameat rename a file attributesystem calls and tags them with the identifier "delete".

Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system a…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor file deletion events by users.

Example:

# {
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
" >> /etc/audit/rules.d/50-delete.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-035: 6.2.3.14 Ensure events that modify the system's Mandatory Access Controls are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.14`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.14` (4 command(s); prefer playbook `ssh_run`).
```bash
/sbin/auditctl -l 2>/dev/null | /bin/awk '/^ *-w/ && /\/etc\/apparmor.d/ && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor AppArmor, an implementation of mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the /etc/apparmor/ and /etc/apparmor.d/ directories.

Note: If a different Mandatory Access Control method is used, changes to the corresponding directories should be audited.

Changes to files in the /etc/apparmor/ and /etc/apparmor.d/ directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of t…
**Remediation (CIS):** Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor events that modify the system's Mandatory Access Controls.

Example:

# printf "
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
" >> /etc/audit/rules.d/50-MAC-policy.rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-036: 6.2.3.15 Ensure successful and unsuccessful attempts to use the chcon command are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.15`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.15` (2 command(s); prefer playbook `ssh_run`).
```bash
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs); [ -n "${UID_MIN}" ] && awk  "(/^ *-a *always,exit/||/^ *-a *exit,always/) &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&/ -F *auid>=${UID_MIN}/ &&/ -F *perm=x/ &&/ -F *path=\/usr\/bin\/chcon/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/) " /etc/audit/rules.d/*.rules | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}' || printf "ERROR: Variable 'UID_MIN' is unset. \n "
# …
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** The operating system must generate audit records for successful/unsuccessful uses of the chcon command.

The chcon command is used to change file security context. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor successful and unsuccessful attempts to use the chcon command.

Example:

# {
 UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
 [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-037: 6.2.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.16`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.16` (2 command(s); prefer playbook `ssh_run`).
```bash
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs); [ -n "${UID_MIN}" ] && auditctl -l | awk  "(/^ *-a *always,exit/||/^ *-a *exit,always/) &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&/ -F *auid>=${UID_MIN}/ &&/ -F *perm=x/ &&/ -F *path=\/usr\/bin\/setfacl/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/) " | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}' || printf  "ERROR: Variable 'UID_MIN' is unset. \n "
# …
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** The operating system must generate audit records for successful/unsuccessful uses of the setfacl command

This utility sets Access Control Lists (ACLs) of files and directories. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor successful and unsuccessful attempts to use the setfacl command.

Example:

# {
 UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
 [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-038: 6.2.3.17 Ensure successful and unsuccessful attempts to use the chacl command are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.17`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.17` (2 command(s); prefer playbook `ssh_run`).
```bash
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs); [ -n "${UID_MIN}" ] && awk  "(/^ *-a *always,exit/||/^ *-a *exit,always/) &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&/ -F *auid>=${UID_MIN}/ &&/ -F *perm=x/ &&/ -F *path=\/usr\/bin\/chacl/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/) " /etc/audit/rules.d/*.rules | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}' || printf  "ERROR: Variable 'UID_MIN' is unset. \n "
# …
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** The operating system must generate audit records for successful/unsuccessful uses of the chacl command.

chacl is an IRIX-compatibility command, and is maintained for those users who are familiar with its use from either XFS or IRIX.

chacl changes the ACL(s) for a file or directory. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the info…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor successful and unsuccessful attempts to use the chacl command.

Example:

# {
 UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
 [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-039: 6.2.3.18 Ensure successful and unsuccessful attempts to use the usermod command are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.18`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.18` (2 command(s); prefer playbook `ssh_run`).
```bash
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs); [ -n "${UID_MIN}" ] && auditctl -l | awk  "(/^ *-a *always,exit/||/^ *-a *exit,always/) &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&/ -F *auid>=${UID_MIN}/ &&/ -F *perm=x/ &&/ -F *path=\/usr\/sbin\/usermod/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/) " | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}' || printf  "ERROR: Variable 'UID_MIN' is unset. \n "
# …
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** The operating system must generate audit records for successful/unsuccessful uses of the usermod command.

The usermod command modifies the system account files to reflect the changes that are specified on the command line. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor successful and unsuccessful attempts to use the usermod command.

Example:

# {
 UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
 [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod
" >> /etc/audit/rules.d/50-usermod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-040: 6.2.3.19 Ensure kernel module loading unloading and modification is collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.19`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.19` (5 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
  &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
  &&/ -F *auid>=${UID_MIN}/ \
  &&/ -F *perm=x/ \
  &&/ -F *path=\/usr\/bin\/kmod/ \
  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
  || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}| /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
# …
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor the loading and unloading of kernel modules. All the loading / listing / dependency checking of modules is done by kmod via symbolic links.

The following system calls control loading and unloading of modules:

 - init_module - load a module
 - finit_module - load a module (used when the overhead of using cryptographically signed modules to determine the authenticity of a module can be avoided)
 - delete_module - delete a module
 - create_module - create a loadable module entry
 - query_module - query the kernel for various bits pertaining to modules

Any execution of the loading and…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor kernel module modification.

Example:

#!/usr/bin/env bash

{
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
  -a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
  -a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
  " >> /etc/audit/rules.d/50-kernel_modules.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-041: 6.2.3.2 Ensure actions as another user are always logged
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.2`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.2` (5 command(s); prefer playbook `ssh_run`).
```bash
/bin/uname -a | /bin/grep x86_64 | /bin/awk '{print} END {if (NR > 0) print "found"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** sudo provides users with temporary elevated privileges to perform operations, either as the superuser or another user.

Creating an audit log of users with temporary elevated privileges and the operation(s) they performed is essential to reporting. Administrators will want to correlate the events written to the audit trail with the records written to sudo 's logfile to verify if unauthorized commands have been executed.
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor elevated privileges.

Example:

# printf "
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
" >> /etc/audit/rules.d/50-user_emulation.rules

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-042: 6.2.3.20 Ensure the audit configuration is immutable
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.20`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/bin/grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | /bin/tail -1
```
- Expect output matching: `^[\s]*-e[\s]+2[\s]*$`.
**Pass criteria:** ^[\s]*-e[\s]+2[\s]*$
**Background:** Set system audit so that audit rules cannot be modified with auditctl . Setting the flag "-e 2" forces audit to be put in immutable mode. Audit changes can only be made on system reboot.

Note: This setting will require the system to be rebooted to update the active auditd configuration settings.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes.
**Remediation (CIS):** Edit or create the file /etc/audit/rules.d/99-finalize.rules and add the line -e 2 at the end of the file:

Example:

# printf '\n%s' "-e 2" >> /etc/audit/rules.d/99-finalize.rules

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-043: 6.2.3.21 Ensure the running and on disk configuration is the same
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.21`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/sbin/augenrules --check
```
- Expect output matching: `^[\s]*/sbin/augenrules:[\s]*No change[\s]*$`.
**Pass criteria:** ^[\s]*/sbin/augenrules:[\s]*No change[\s]*$
**Background:** The Audit system have both on disk and running configuration. It is possible for these configuration settings to differ.

Note: Due to the limitations of augenrules and auditctl, it is not absolutely guaranteed that loading the rule sets via augenrules --load will result in all rules being loaded or even that the user will be informed if there was a problem loading the rules.

Configuration differences between what is currently running and what is on disk could cause unexpected problems or may give a false impression of compliance requirements.
**Remediation (CIS):** If the rules are not aligned across all three () areas, run the following command to merge and load all rules:

# augenrules --load

Check if reboot is required.

if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then echo "Reboot required to load rules"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-044: 6.2.3.3 Ensure events that modify the sudo log file are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.3`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.3` (2 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash
      {
        SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g')
        [ -n "${SUDO_LOG_FILE}" ] && auditctl -l | awk "/^ *-w/ \
        &&/"${SUDO_LOG_FILE}"/ \
        &&/ +-p *wa/ \
        &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" \
        || printf "ERROR: Variable 'SUDO_LOG_FILE' is unset.\n"
      } | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
# …
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor the sudo log file. If the system has been properly configured to disable the use of the su command and force all administrators to have to log in first and then use sudo to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log . Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will be opened for write and the executed administration command will be written to the log.

Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file itself has been tampered with.…
**Remediation (CIS):** Note: This recommendation requires that the sudo logfile is configured. See guidance provided in the recommendation "Ensure sudo log file exists"

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor events that modify the sudo log file.

Example:

# {
SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g')
[ -n "${SUDO_LOG_FILE}" ] && printf "
-w ${SUDO_LOG_FILE} -p wa -k sudo_log_file
" >> /etc/audit/rules.d/50-sudo.rules || printf "ERROR: Variable 'SUDO_LOG_FILE' is unset.\n"
}

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-045: 6.2.3.4 Ensure events that modify date and time information are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.4`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.4` (15 command(s); prefer playbook `ssh_run`).
```bash
/bin/uname -a | /bin/grep x86_64 | /bin/awk '{print} END {if (NR > 0) print "found"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the;

 - adjtimex - tune kernel clock
 - settimeofday - set time using timeval and timezone structures
 - stime - using seconds since 1/1/1970
 - clock_settime - allows for the setting of several internal clocks and timers

system calls have been executed. Further, ensure to write an audit record to the configured audit log file upon exit, tagging the records with a unique identifier such as "time-change".

Unexpected changes in system date and/or time could be a sign of…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor events that modify date and time information.

Example:

# printf "
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
" >> /etc/audit/rules.d/50-time-change.rules

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-046: 6.2.3.5 Ensure events that modify the system's network environment are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.5`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.5` (20 command(s); prefer playbook `ssh_run`).
```bash
/bin/awk '/^ *-w/ &&/\/etc\/network\// &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Record changes to network environment files or system calls. The below parameters monitors the following system calls, and write an audit event on system call exit:

 - sethostname - set the systems host name
 - setdomainname - set the systems domain name

The files being monitored are:

 - /etc/issue and /etc/issue.net - messages displayed pre-login
 - /etc/hosts - file containing host names and associated IP addresses
 - /etc/networks - symbolic names for networks
 - /etc/network/ - directory containing network interface scripts and configurations files
 - /etc/netplan/ - central location f…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor events that modify the system's network environment.

Example:

# printf "
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
" >> /etc/audit/rules.d/50-system_locale.rules

Load audit rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-047: 6.2.3.6 Ensure use of privileged commands are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.6`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.6` (2 command(s); prefer playbook `ssh_run`).
```bash
RUNNING=$(/sbin/auditctl -l); [ -n "${RUNNING}" ] && for PARTITION in $(/bin/findmnt -n -l -k -it $(/bin/awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | /bin/grep -Pv "noexec|nosuid" | /bin/awk '{print $1}'); do for PRIVILEGED in $(/bin/find "${PARTITION}" -xdev -perm /6000 -type f); do printf -- "${RUNNING}" | /bin/grep -q "${PRIVILEGED}" && printf "OK: '${PRIVILEGED}' found in auditing rules.\n" || printf "Warning: '${PRIVILEGED}' not found in running configuration.\n"; done; done | /bin/awk '{print} END { if ($1 ~ "Warning") print "Fail - Warnings found"; else print "Pass - No warning entries found" }'
# …
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor privileged programs, those that have the setuid and/or setgid bit set on execution, to determine if unprivileged users are running these commands.

Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system.
**Remediation (CIS):** Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor the use of privileged commands.

Example script:

#!/usr/bin/env bash

{
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-privileged.rules"
  NEW_DATA=()
  for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
    readarray -t DATA < <(find "${PARTITION}" -xdev -perm /6000 -type f | awk -v UID_MIN=${UID_MIN} '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>="UID_MIN" -F auid!=unset -k privileged" }')
      for ENTRY in "${DATA[@]}"; do
        NEW_DATA+=("${ENTRY}")
      done
  done
  readarray &> /dev/null -t OLD_DATA < "${AUDIT_RULE_FILE}"
  COMBINED_DATA=( "${OLD_DATA[@]}" "${NEW_DATA[@]}" )
  printf '%s\n'…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-048: 6.2.3.7 Ensure unsuccessful file access attempts are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.7`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.7` (9 command(s); prefer playbook `ssh_run`).
```bash
/bin/uname -a | /bin/grep x86_64 | /bin/awk '{print} END {if (NR > 0) print "found"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor for unsuccessful attempts to access files. The following parameters are associated with system calls that control files:

 - creation - creat
 - opening - open, openat
 - truncation - truncate, ftruncate

An audit log record will only be written if all of the following criteria is met for the user when trying to access a file:

 - a non-privileged user (auid>=UID_MIN)
 - is not a Daemon event (auid=4294967295/unset/-1)
 - if the system call returned EACCES (permission denied) or EPERM (some other permanent error associated with the specific system call)

Failed attempts to open, creat…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor unsuccessful file access attempts.

Example:

# {
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
" >> /etc/audit/rules.d/50-access.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

Load audit rul…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-049: 6.2.3.8 Ensure events that modify user/group information are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.8`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.8` (16 command(s); prefer playbook `ssh_run`).
```bash
/bin/awk '/^ *-w/ &&/\/etc\/shadow/ &&/ +-p *wa/  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules | /bin/awk '{print} END {if (NR != 0) print "pass" ; else print "fail"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Record events affecting the modification of user or group information, including that of passwords and old passwords if in use.

 - /etc/group - system groups
 - /etc/passwd - system users
 - /etc/gshadow - encrypted password for each group
 - /etc/shadow - system user passwords
 - /etc/security/opasswd - storage of old passwords if the relevant PAM module is in use
 - /etc/nsswitch.conf - file configures how the system uses various databases and name resolution mechanisms
 - /etc/pam.conf - file determines the authentication services to be used, and the order in which the services are used.…
**Remediation (CIS):** Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor events that modify user/group information.

Example:

# printf "
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
" >> /etc/audit/rules.d/50-identity.rules

Merge and load the rules into active configuration:

# augenrules --load

Check if reboot is required.

# if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-050: 6.2.3.9 Ensure discretionary access control permission modification events are collected
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.3.9`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.3.9` (53 command(s); prefer playbook `ssh_run`).
```bash
/bin/uname -a | /bin/grep x86_64 | /bin/awk '{print} END {if (NR > 0) print "found"}'
```
- Expect output matching: `composite: all condition checks must pass`.
**Pass criteria:** composite: all condition checks must pass
**Background:** Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The following commands and system calls effect the permissions, ownership and various attributes of files.

 - chmod
 - fchmod
 - fchmodat
 - chown
 - fchown
 - fchownat
 - lchown
 - setxattr
 - lsetxattr
 - fsetxattr
 - removexattr
 - lremovexattr
 - fremovexattr

In all cases, an audit record will only be written for non-system user ids and will ignore Daemon events. All audit records will be tagged with the identifi…
**Remediation (CIS):** Create audit rules

Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension, with the relevant rules to monitor discretionary access control permission modification events.

Example:

# {
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-051: 6.2.4.1 Ensure audit log files mode is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.1`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.4.1` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_perm_mask="0137"
   if [ -e "/etc/audit/auditd.conf" ]; then
      l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
      if [ -d "$l_audit_log_directory" ]; then
         l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
         a_files=()
         while IFS= read -r -d $'\0' l_file; do
            [ -e "$l_file" ] && a_files+=("$l_file")
         done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -perm /"$l_perm_mask" -print0)
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** Audit log files contain information about the system and system activity.

Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.
**Remediation (CIS):** Run the following command to remove more permissive mode than 0640 from audit log files:

# [ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-052: 6.2.4.10 Ensure audit tools group owner is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.10`
**How to verify:** - Check type: `FILE_CHECK`.
- SSH: inspect `/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules`.
**Pass criteria:** Audit probe reports PASS / expected pattern matches.
**Background:** Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Protecting audit tools is necessary to prevent unauthorized operation on audit information.
**Remediation (CIS):** Run the following command to change group ownership to the groop root :

# chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-053: 6.2.4.2 Ensure audit log files owner is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.2`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.4.2` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_output="" l_output2=""
   if [ -e "/etc/audit/auditd.conf" ]; then
      l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
      if [ -d "$l_audit_log_directory" ]; then
         while IFS= read -r -d $'\0' l_file; do
            l_output2="$l_output2\n  - File: \"$l_file\" is owned by user: \"$(stat -Lc '%U' "$l_file")\"\n     (should be owned by user: \"root\")\n"
         done < <(find "$l_audit_log_directory" -maxdepth 1 -type f ! -user root -print0)
      else
         l_output2="$l_output2\n  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** Audit log files contain information about the system and system activity.

Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.
**Remediation (CIS):** Run the following command to configure the audit log files to be owned by the root user:

# [ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec chown root {} +
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-054: 6.2.4.3 Ensure audit log files group owner is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.3`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.4.3` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
  l_output="" l_output2=""
  if [ -e "/etc/audit/auditd.conf" ]; then
    l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
    l_audit_log_group="$(awk -F= '/^\s*log_group\s*/{print $2}' /etc/audit/auditd.conf | xargs)"
    if grep -Pq -- '^\h*(root|adm)\h*$' <<< "$l_audit_log_group"; then
      l_output="$l_output\n - Log file group correctly set to: \"$l_audit_log_group\" in \"/etc/audit/auditd.conf\""
    else
      l_output2="$l_output2\n - Log file group is set to: \"$l_audit_log_group\" in \"/etc/audit/auditd.conf\"\n (should be set to group: \"root or adm\")\n"
    fi
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** Audit log files contain information about the system and system activity.

Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.
**Remediation (CIS):** Run the following command to configure the audit log files to be group owned by adm :

# find $(dirname $(awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)) -type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} +

Run the following command to set the log_group parameter in the audit configuration file to log_group = adm :

# sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' /etc/audit/auditd.conf

Run the following command to restart the audit daemon to reload the configuration file:

# systemctl restart auditd
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-055: 6.2.4.4 Ensure the audit log file directory mode is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.4`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.4.4` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   l_perm_mask="0027"
   if [ -e "/etc/audit/auditd.conf" ]; then
      l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
      if [ -d "$l_audit_log_directory" ]; then
         l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
         l_directory_mode="$(stat -Lc '%#a' "$l_audit_log_directory")"
         if [ $(( $l_directory_mode & $l_perm_mask )) -gt 0 ]; then
            echo -e "\n- Audit Result:\n  ** FAIL **\n  - Directory: \"$l_audit_log_directory\" is mode: \"$l_directory_mode\"\n     (should be mode: \"$l_maxperm\" or more restrictive)\n"
         else
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** The audit log directory contains audit log files.

Audit information includes all information including: audit records, audit settings and audit reports. This information is needed to successfully audit system activity. This information must be protected from unauthorized modification or deletion. If this information were to be compromised, forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.
**Remediation (CIS):** Run the following command to configure the audit log directory to have a mode of "0750" or less permissive:

# chmod g-w,o-rwx "$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-056: 6.2.4.5 Ensure audit configuration files mode is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.5`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.2.4.5` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

  {
   l_output="" l_output2="" l_perm_mask="0137"
   l_maxperm="$( printf '%o' $(( 0777 & ~$l_perm_mask )) )"
   while IFS= read -r -d $'\0' l_fname; do
      l_mode=$(stat -Lc '%#a' "$l_fname")
      if [ $(( "$l_mode" & "$l_perm_mask" )) -gt 0 ]; then
         l_output2="$l_output2\n - file: \"$l_fname\" is mode: \"$l_mode\" (should be mode: \"$l_maxperm\" or more restrictive)"
      fi
   done < <(find /etc/audit/ -type f \( -name "*.conf" -o -name '*.rules' \) -print0)
   if [ -z "$l_output2" ]; then
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** Audit configuration files control auditd and what events are audited.

Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events.

Misconfigured audit configuration files may prevent the auditing of critical events or impact the system's performance by overwhelming the audit log. Misconfiguration of the audit configuration files may also make it more difficult to establish and investigate events relating to an incident.
**Remediation (CIS):** Run the following command to remove more permissive mode than 0640 from the audit configuration files:

# find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-057: 6.2.4.6 Ensure audit configuration files owner is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.6`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/bin/find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root | /bin/awk '{print} END { if(NR==0) print "pass" ; else print "fail"}'
```
- Expect output matching: `^pass$`.
**Pass criteria:** ^pass$
**Background:** Audit configuration files control auditd and what events are audited.

Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events.

Misconfigured audit configuration files may prevent the auditing of critical events or impact the system's performance by overwhelming the audit log. Misconfiguration of the audit configuration files may also make it more difficult to establish and investigate events relating to an incident.
**Remediation (CIS):** Run the following command to change ownership to root user:

# find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-058: 6.2.4.7 Ensure audit configuration files group owner is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.7`
**How to verify:** - Check type: `CMD_EXEC`.
SSH run:
```bash
/bin/find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root | /bin/awk '{print} END { if(NR==0) print "pass" ; else print "fail"}'
```
- Expect output matching: `^pass$`.
**Pass criteria:** ^pass$
**Background:** Audit configuration files control auditd and what events are audited.

Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events.

Misconfigured audit configuration files may prevent the auditing of critical events or impact the system's performance by overwhelming the audit log. Misconfiguration of the audit configuration files may also make it more difficult to establish and investigate events relating to an incident.
**Remediation (CIS):** Run the following command to change group to root :

# find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-059: 6.2.4.8 Ensure audit tools mode is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.8`
**How to verify:** - Check type: `FILE_CHECK`.
- SSH: inspect `/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules`.
**Pass criteria:** Audit probe reports PASS / expected pattern matches.
**Background:** Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Protecting audit tools is necessary to prevent unauthorized operation on audit information.
**Remediation (CIS):** Run the following command to remove more permissive mode from the audit tools:

# chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-060: 6.2.4.9 Ensure audit tools owner is configured
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.2.4.9`
**How to verify:** - Check type: `FILE_CHECK`.
- SSH: inspect `/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules`.
**Pass criteria:** Audit probe reports PASS / expected pattern matches.
**Background:** Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Protecting audit tools is necessary to prevent unauthorized operation on audit information.
**Remediation (CIS):** Run the following command to change the owner of the audit tools to the root user:

# chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
**See also:** https://workbench.cisecurity.org/benchmarks/18959

## REQ-061: 6.3.3 Ensure cryptographic mechanisms are used to protect the integrity of audit tools
**Category:** Logging and Auditing
**Severity:** High
**CIS ID:** `6.3.3`
**How to verify:** - Check type: `CMD_EXEC`.
- SSH: run the CIS audit probe script(s) for `6.3.3` (1 command(s); prefer playbook `ssh_run`).
```bash
#!/bin/bash

{
   a_output=() a_output2=() l_tool_dir="$(readlink -f /sbin)"
   a_items=("p" "i" "n" "u" "g" "s" "b" "acl" "xattrs" "sha512");
   l_aide_cmd="$(whereis aide | awk '{print $2}')"
   a_audit_files=("auditctl" "auditd" "ausearch" "aureport" "autrace" "augenrules");
   if [ -f "$l_aide_cmd" ] && command -v "$l_aide_cmd" &>/dev/null; then
      a_aide_conf_files=("$(find -L /etc -type f -name 'aide.conf')")
      f_file_par_chk()
      {
         a_out2=()
# …
```
- Expect output matching: `(?i)^[\s]*\**[\s]*pass:?[\s]*\**$`.
**Pass criteria:** (?i)^[\s]*\**[\s]*pass:?[\s]*\**$
**Background:** Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

aide.conf is case-sensitive. Leading and trailing white spaces are ignored. Each config lines must end with new line.

AIDE uses the backslash character \ as escape character for ' ' (space), '@' and '' (backslash) (e.g. '\ ' or '@'). To literally match a '' in a file path with a regular expression you have to escape the backslash twice (i.e. '\\').

There ar…
**Remediation (CIS):** Run the following command to determine the absolute path to the non-symlinked version on the audit tools:

# readlink -f /sbin

The output will be either /usr/sbin - OR - /sbin . Ensure the correct path is used.

Edit /etc/aide/aide.conf and add or update the following selection lines replacing <PATH> with the correct path returned in the command above:

# Audit Tools
<PATH>/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

Example

# printf '%s\n' "" "# Audit Tools" "$(readlink -f /sbin/auditctl) p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/auditd) p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/ausearch) p+i+n+u+g+s+b+acl+xattrs+sha512" "$(rea…
**See also:** https://workbench.cisecurity.org/benchmarks/18959

---
id: cisco_device
aliases: [cisco, ios, ios-xe, network switch]
description: Cisco network device identity and baseline (SNMP discovery)
domain: cybersecurity
language: en
family_id: cisco_device
type: audit
title: Cisco Device Assessment
version: "1.0"
applicability:
  all:
    - fact: asset.type
      operator: in
      value: [network_device, network, switch, router, firewall]
  any:
    - fact: asset.vendor
      operator: equals
      value: cisco
required_capabilities:
  any_of:
    - snmp.get
required_facts:
  - asset.vendor
  - asset.type
discovery_hints:
  - capability: snmp.get
    purpose: Read Cisco sysDescr / sysObjectID
    arguments:
      oids:
        - 1.3.6.1.2.1.1.1.0
        - 1.3.6.1.2.1.1.2.0
    expected_facts:
      - asset.vendor
      - os.family
      - asset.model
---
# Cisco Device Assessment

## REQ-001: Device identity
**Category:** Inventory
**Severity:** High
**How to verify:** Read sysDescr and sysObjectID via SNMP GET.
**Pass criteria:** Vendor, model, and OS family are recorded from SNMP evidence.

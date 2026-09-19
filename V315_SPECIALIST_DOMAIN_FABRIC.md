# V3.15 — Specialist Domain Fabric

V3.15 expands the platform around four domains that specialist tools currently handle better than a general orchestrator: wireless, remote systems, mobile devices, and RCE/exploitability validation.

## Research-derived capabilities

- **Wireless:** Aircrack-ng's monitoring/testing/capture-oriented suite, Kismet-style passive discovery, and bettercap's cross-wireless/BLE/network visibility informed the wireless layer.
- **Mobile:** MobSF + Frida + Objection were combined with Corellium-style virtual-device lifecycle, introspection, snapshots and network observation.
- **Remote systems:** Nmap/NetExec/Metasploit patterns informed a protocol matrix, service-to-identity correlation and evidence-backed remote-session modeling.
- **RCE:** Metasploit/Nuclei-style candidate discovery is separated from exploitability validation. A candidate must satisfy prerequisites and use a governed validation contract.

## Core transformation

The platform is not becoming a collection of copied tools. It becomes the **control plane** above specialist engines:

`specialist observation -> normalized evidence -> cross-domain correlation -> hypothesis -> exact-action approval -> specialist execution -> evidence -> verdict -> retest`

## Wireless

Supports radio/interface capability inventory, passive Wi-Fi discovery, PCAP normalization, BLE inventory, hardware prerequisite checks and explicit active-validation contracts.

## Remote systems

The protocol matrix covers SSH, SMB, WinRM, RDP, LDAP, SNMP, HTTP/S, DNS, NFS and FTP. Discovery and read-only assessment are separated from active validation. Session state is represented as ephemeral evidence references rather than reusable credential storage.

## Mobile

The mobile fabric models artifact analysis, runtime instrumentation, component attack-surface review, virtual-device provisioning, snapshots/restores, filesystem/process/syscall observation and network-trace correlation.

## RCE

RCE is handled as a lifecycle:

`candidate -> preconditions -> safe proof contract -> validation -> verdict -> attack-path correlation -> remediation -> retest`

The system never treats a version/CVE match as proof of remote code execution.

## Governance

Every active operation remains subject to authorization, authoritative scope, ROE, exact-action approval, ToolManager allowlisting, executable identity verification, evidence provenance and kill-switch conditions. Device authorization is separate from application authorization.

# V3.15 — Specialist Domain Fabric

## Added
- Wireless specialist fabric: radio inventory, passive Wi-Fi/PCAP normalization, BLE inventory, hardware prerequisite assurance and governed active-scenario contracts.
- Mobile specialist fabric: static/runtime workflow, Android component surface, virtual-device lifecycle, snapshots/restores, filesystem/process/syscall introspection and API/network correlation contracts.
- Remote-system protocol matrix covering SSH, SMB, WinRM, RDP, LDAP, SNMP, HTTP/S, DNS, NFS and FTP, with service/identity/path correlation.
- RCE validation lifecycle: candidate discovery, prerequisite analysis, safe proof contracts, exploitability verdicts, attack-path correlation and remediation retest.
- Cross-domain fusion connecting wireless → remote → identity → RCE and mobile → web/cloud evidence.
- CLI fabric actions for specialist-domain planning.

## Governance
- Active operations remain behind authorization, authoritative scope, ROE and exact-action approval.
- Device authorization is separated from application authorization.
- No unrestricted payload/C2 generation was added.
- RCE candidate discovery never becomes proof of execution automatically.

## Validation
- Full pytest suite: 100% passing.
- Added V3.15 specialist-domain regression tests.

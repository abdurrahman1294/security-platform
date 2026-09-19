# V2.3 Capability-Gap Audit & Versatility Expansion

## Decision
V2.2 had broad web/API/network/AD/AWS/OSINT/bounty coverage but Android/mobile and wireless were not first-class specialist domains. V2.3 promotes both to first-class domains while preserving the platform's authorization, evidence, and scope boundaries.

## Priority matrix

| Domain | V2.2 | V2.3 | Priority | Next depth |
|---|---|---|---|---|
| Android APK/static | partial | strong foundation | P0 | runtime instrumentation, network correlation, native review |
| Android emulator/device | planned | read-only inspection | P0 | controlled dynamic lab instrumentation |
| Wi-Fi | planning/catalog | interface + passive/PCAP foundation | P0 | controlled monitor-mode lab capture, 802.11 analysis |
| BLE | planned | roadmap | P2 | advertisement/GATT assessment |
| Network services | partial | partial | P1 | UDP/SNMP/NFS/SMTP/DNS/TLS depth |
| Windows/AD | partial | partial | P1 | Kerberos/ACL/delegation/GPO lab validation |
| Cloud | partial | partial | P1 | Azure/Entra/GCP parity, Kubernetes |
| iOS | planned | roadmap | P2 | IPA/static/simulator assessment |
| Physical/social | not automated | operator-led only | P3 | separate governance and exercise tooling |

## Android V2.3 foundation
- APK ZIP/structure inspection
- Manifest parsing when text is available
- `aapt`/`aapt2`/`apkanalyzer` integration when installed
- permissions and exported component review
- cleartext/debuggable/backup heuristics
- WebView indicators
- native library inventory
- embedded URL/secret-marker detection with redaction
- read-only ADB inspection for emulators
- explicit opt-in for physical-device read-only inspection

Android coverage is aligned with the security concerns emphasized by Android Developers, including sandboxing, permissions, secure communication, data storage, WebView boundaries, API-key handling, and native-code risk. See the Android security guidance in the project references.

## Wireless V2.3 foundation
- wireless interface inventory
- radio/driver capability observation
- NetworkManager state
- existing PCAP analysis
- SSID/BSSID/frequency extraction
- explicit restricted-action boundary
- tool catalog entries for Aircrack-ng, Kismet, tshark, iw, airmon-ng and airodump-ng

The engine deliberately does not automate deauthentication, frame injection, credential cracking, rogue-AP operation, or uncontrolled capture. Those actions remain operator-controlled and separately governed.

## Architecture
```text
Security Platform
├── Pentest Engine
├── Bug Bounty Engine
├── OSINT Engine
├── Mobile Engine (V2.3)
│   └── Android assessment
└── Wireless Engine (V2.3)
    └── Wi-Fi/passive radio/PCAP assessment
```

## Coverage rule
A capability counts as covered only when it produces evidence-backed execution. A checklist, tool name, or future roadmap item is not counted as completed capability.

# V3.16 — Embedded / IoT / OT / ICS / Automotive / Hardware Fabric

V3.16 extends the V3.15 specialist control plane into cyber-physical and embedded security. It combines firmware analysis, low-level platform security, IoT networking, OT/ICS assessment, automotive CAN/diagnostic analysis, and network-device security into one evidence-driven fabric.

## Research basis
- Binwalk / EMBA / FACT: firmware extraction, component analysis, SBOM, static/dynamic analysis and reporting.
- CHIPSEC / OpenOCD: platform/firmware security and controlled hardware/debug-interface assessment.
- ICS security ecosystems: protocol-aware, safety-aware OT assessment and MITRE ATT&CK for ICS mapping.
- can-utils / Caring Caribou / SavvyCAN / ICSim / UDSim: CAN capture, analysis, ECU/diagnostic modeling and safe vehicle simulation.

## Architecture
`artifact/device observation -> normalized evidence -> domain graph -> safety classification -> exact approval -> specialist execution -> evidence -> verdict -> retest`

The fabric does not silently modify firmware, controllers, vehicles, PLCs or network devices. State-changing and process-impacting operations remain approval-gated and lab/testbed constrained.

## New domains
1. Firmware security pipeline
2. Hardware/platform security
3. IoT device/network security
4. OT/ICS protocol and safety-aware assessment
5. Automotive CAN/UDS/ECU security
6. Network-device security
7. Cross-domain physical-to-digital attack-path correlation

## Safety model
S0 = offline/passive; S1 = read-only; S2 = bounded non-disruptive validation; S3 = isolated lab/testbed validation; S4 = process-impacting or hardware-writing and never autonomous.

# V3.17 — Remote Endpoint & Advanced Analysis Fabric

V3.17 extends the governed control plane into comprehensive authorized remote assessment of computers and mobile devices and adds advanced firmware, reverse-engineering, protocol-fuzzing, digital-twin/testbed and physical-interface correlation workflows.

## Remote computers
Windows, Linux and macOS plans model approved remote channels, endpoint evidence, authenticated assessment, service/application validation, identity and attack-path correlation, isolated reproduction, remediation retest and reporting.

## Remote phones
Android supports approved ADB/management/emulator paths. iOS supports Corellium, simulator/runtime and explicitly authorized instrumented/jailbroken-device channels. A normal consumer iOS device does not expose arbitrary remote inspection merely because it is reachable on a network.

## Advanced analysis
- Firmware: QEMU/FirmAE/EMBA/FACT-style identify → extract → architecture → rehost → runtime observation → diff/retest.
- Reverse engineering: Ghidra/radare2/angr-style disassembly, decompilation, CFG/call graph, data-flow, trace correlation and patch diff.
- Protocol fuzzing: grammar/state-machine models, seed corpora, bounded mutation, rate/budget controls, crash/hang oracles, deduplication and minimization.
- Digital twins/testbeds: snapshots, instrumentation, state seeding, scenario execution, restore and comparison.
- Physical correlation: JTAG/SWD/UART/SPI/I2C/USB/PCIe/CAN/GPIO evidence linked to firmware, captures, device state and digital-twin observations.

## Governance
The fabric does not create unrestricted remote shells, credential theft/capture, stealth/evasion, persistence deployment, destructive operations or uncontrolled propagation. Remote channels are capabilities to assess; they do not themselves grant execution authority. Exact active actions remain subject to authorization, scope, ToolManager allowlisting, approval, rate/time budgets, kill switch and audit logging.

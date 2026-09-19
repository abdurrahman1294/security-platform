# V3.12 — Adaptive Mission & Capability Fusion

The platform now supports a closed-loop planning model:

**observe → score → select specialist → execute through existing authorization/scope gate → ingest evidence → re-plan**.

It also records higher-order capability compositions, where several specialist
engines together provide a stronger workflow than any one scanner.

## Specialist depth

The controller treats Metasploit, Cobalt Strike-style adversary-emulation
workflows, BloodHound, MobSF, ProjectDiscovery, NetExec, Frida, SARIF tools,
and other ecosystems as specialist sources rather than attempting to replace
their mature implementations wholesale.

## Safety boundary

This release does not implement weaponized C2, payload generation, credential
capture/theft, persistence deployment, evasion, destructive actions, or
unrestricted remote command execution. Consequential validation remains behind
existing engagement authorization, ROE, scope, and approval gates.

## Cobalt Strike / Metasploit coverage strategy

The target is **workflow coverage and orchestration parity**, not cloning
proprietary code. Specialist adapters may consume approved results and invoke
existing registered tools only through the platform's existing hardened tool
contracts. Lab-only adversary-emulation metadata can be used to map ATT&CK
coverage and detection-validation objectives.

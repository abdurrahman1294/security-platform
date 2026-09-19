# V3.20 Universal Attack-Surface Fabric

V3.20 turns the platform from a collection of specialist domains into a common attack-surface assessment plane.

## Coverage

The fabric models 35 surface classes including web/API, DNS/certificates, Internet services, remote access, Windows/Linux/macOS endpoints, identity, cloud/SaaS, containers, virtualization, network devices, wireless, Android/iOS, IoT, firmware, hardware debug interfaces, OT/ICS, automotive, databases, storage/backups, email/collaboration, supply chain, CI/CD, secrets/keys, management planes, third-party integrations, browsers/desktop clients, human processes, physical facilities, AI/ML applications, and cellular/telecom exposure.

## Perspectives

Each surface can be assessed from multiple observation origins: local host, physical/adjacent lab, LAN, enterprise segment, public IPv4, public IPv6, cellular IPv4, cellular IPv6, VPN, cloud vantage, authenticated user, administrative user, digital testbed, and physical lab.

A perspective is a vantage point, not permission. Reachability remains an evidence question.

## Functional execution

V3.20 maps surfaces to the platform's already-governed executable adapters (`subfinder`, `httpx`, `katana`, `naabu`, `nmap`, `nuclei`, `nxc`, `aws`, `az`, `gcloud`, `kubectl`). New execution paths must continue through `ToolManager`; V3.20 does not introduce arbitrary shell execution.

Domains without a generic safe adapter remain specialist- or artifact-driven (for example firmware, hardware, automotive, OT, physical and human-process testing). Those domains are still reachable through their existing specialist fabrics and testbeds.

## Security factors

The factor graph captures exposure, addressing, network path, trust boundaries, identity, authentication, authorization, software/version, configuration, protocol state, cryptography, secrets, dependencies, supply chain, management planes, remote access, physical access, human process, data sensitivity, third-party trust, cloud control planes, container runtime, mobile permissions, firmware update chains, debug interfaces, telemetry/detection, backup/recovery, segmentation, and state/time.

## Execution model

- R0: observe/correlate
- R1: bounded discovery
- R2: non-destructive verification
- R3: isolated testbed validation
- R4: separately governed consequential validation
- R5: denied autonomous destructive/covert/propagating activity

No surface automatically grants authority. No perspective bypasses scope or authorization.

## Research basis

The taxonomy is informed by MITRE ATT&CK Enterprise, Mobile and ICS domains, OWASP WSTG, OWASP API Security, OWASP MASVS/MASTG, NIST SP 800-115, NIST CSF 2.0, and CIS Controls v8.1. These sources reinforce asset inventory, attack-surface identification, identity/control-plane analysis, application/API testing, mobile testing, and multi-environment coverage as complementary rather than interchangeable assessment activities.

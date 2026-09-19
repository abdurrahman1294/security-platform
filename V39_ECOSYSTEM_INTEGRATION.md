# V3.9 Open-Source Security Ecosystem Integration

V3.9 adds a controlled integration layer for major open-source security projects.
The platform reuses specialist tools and evidence formats instead of copying their
implementations, while keeping authorization, scope, evidence provenance and
reporting authoritative inside the platform.

## Integrated evidence families

- ProjectDiscovery: existing native toolchain plus normalized finding import
- BloodHound CE: offline AD/Azure graph export and attack-path candidate analysis
- MobSF: offline mobile-security report normalization
- Nuclei/compatible JSON or JSONL: normalized external finding import
- Metasploit, Sliver and Havoc: capability catalog and lab-only bridge classification
- Impacket and NetExec: Windows/AD protocol and enumeration integration classification
- Frida: runtime instrumentation evidence integration classification
- Hashcat: offline credential-audit result integration classification
- Responder: internal-network research/lab-only classification

## High-risk boundary

V3.9 deliberately does not add autonomous C2, payload generation, credential theft,
persistence deployment, evasion/anti-detection behavior, or unrestricted command
execution. Those capabilities remain catalogued as specialist/lab-only capabilities.

## CLI

Build the integration matrix:

```bash
python securityctl.py ecosystem -c client -t target -o output --action matrix
```

Import a BloodHound export:

```bash
python securityctl.py ecosystem -c client -t target -o output --action bloodhound --input bloodhound.json
```

Import a MobSF report:

```bash
python securityctl.py ecosystem -c client -t target -o output --action mobsf --input mobsf.json
```

Import Nuclei-compatible JSON/JSONL:

```bash
python securityctl.py ecosystem -c client -t target -o output --action findings --input findings.jsonl --source-name Nuclei
```

All imported results remain candidates until the platform's evidence/validation
rules independently support a stronger finding state.

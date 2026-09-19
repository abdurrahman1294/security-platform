# V3.10 Ecosystem Capability Fabric

V3.10 builds on the uploaded v3.9 codebase. It does not replace or overwrite the
operator's existing modules. It adds a shared interoperability layer for major
open-source security ecosystems.

## Added integrations

- NetExec result normalization (offline JSON/JSONL)
- Frida runtime-evidence normalization (offline JSON/JSONL)
- Hashcat result summarization without retaining recovered secrets
- Metasploit result normalization without launching modules
- Responder log summarization without capture/poisoning
- Cross-domain investigation-plan generation
- Expanded ecosystem capability matrix

## Architectural rule

The platform owns policy, authorization, scope, evidence provenance, normalization,
correlation and reporting. Specialist projects remain specialist engines. Their
source code is not copied into this repository.

## High-risk boundary

No autonomous C2, payload generation, credential capture, persistence, evasion,
relay/poisoning, or arbitrary command execution was added. Specialist outputs do
not grant authority or expand scope.

## CLI examples

```text
python securityctl.py ecosystem -c client -t target -o output --action matrix
python securityctl.py ecosystem -c client -t target -o output --action netexec --input result.json
python securityctl.py ecosystem -c client -t target -o output --action frida --input runtime.jsonl
python securityctl.py ecosystem -c client -t target -o output --action hashcat --input audit.txt
python securityctl.py ecosystem -c client -t target -o output --action metasploit --input result.json
python securityctl.py ecosystem -c client -t target -o output --action responder --input responder.log
```

All imported observations remain candidates until independently validated by the
platform's evidence controls.

# V3.9 — Open-Source Ecosystem Integration

- Added `modules/ecosystem_adapters_v39.py`.
- Added offline BloodHound CE export analysis.
- Added MobSF report normalization.
- Added generic JSON/JSONL external finding import for Nuclei/ProjectDiscovery-style output.
- Added ecosystem capability/gap matrix covering ProjectDiscovery, Metasploit, Sliver, Havoc, Impacket, NetExec, BloodHound, MobSF, Frida, Hashcat and Responder.
- Added `securityctl ecosystem` CLI workflow.
- Extended the capability matrix and tool catalog.
- Preserved the existing high-risk boundary: no autonomous C2, payload generation, credential theft, persistence, evasion or arbitrary command execution.
- Full test suite passes after the integration.

## V3.11 — Superior Capability Fabric

- Added multi-role agentic assessment planning with dependencies, bounded parallelism and resume keys.
- Added SARIF normalization for source-analysis ecosystems and source/runtime correlation.
- Added browser/proxy HAR evidence normalization for workflow and regression modeling.
- Added continuous-assurance change fingerprints and bounded reassessment planning.
- Added benchmark-quality execution/proof/QA metrics.
- Added provider-agnostic model routing and offline/local model policy metadata.
- Added ATT&CK/Atomic-style emulation metadata import for coverage and detection-validation planning.

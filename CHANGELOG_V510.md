# V5.1.0 — Capability Fusion Depth

## Added (original implementations; no third-party source copied)

### From PentestGPT-documented architecture
- **Pentesting Task Tree (PTT)** with phase nodes and status attributes
- **Reasoning / Generation / Parsing** deterministic agent cycle
- **Live walkthrough journal** (`walkthrough-v510.jsonl`)

### From HexStrike-documented architecture
- **Findings auto-import** for Nmap XML, Nuclei JSONL, httpx JSON
- **Process ledger** (SQLite) for tool run tracking
- **Two-phase port pipeline planner** (fast discovery → service detection)
- **SARIF export** from imported findings

### Ethical multi-role (not Xanthorox criminal features)
- **Offline/local-first role matrix** (reasoner, generator, parser, reporter, vision_evidence)
- **Evidence image register** (path + hash metadata only)
- Explicit **forbidden** list: malware, ransomware, phishing generation, deepfakes, covert C2

## Governance unchanged
Authorization, scope, registered adapters, no arbitrary shell.

## CLI
```bash
python securityctl.py fusion-v51 -c LAB -t 127.0.0.1 -o out --action episode
python securityctl.py fusion-v51 -c LAB -t 127.0.0.1 -o out --action import --import-files scan.xml
python securityctl.py fusion-v51 -c LAB -t 127.0.0.1 -o out --action port-pipeline
python securityctl.py fusion-v51 -c LAB -t 127.0.0.1 -o out --action status
```

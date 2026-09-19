# Changelog — V2.6

## Operational maturity and feature solidification

### Added
- `modules/operational_maturity_v26.py`
- Artifact SHA-256 inventory
- Cross-engine evidence correlation
- Evidence-backed coverage accounting
- Phase/run state ledger with secret redaction
- Toolchain health/dependency state
- `securityctl platform --maturity`
- `tools/v26_maturity_gate.py`

### Hardened
- All registered engines report V2.6 consistently.
- Pentest phase execution now records phase state.
- Pentest runs include a bounded maturity summary after execution.
- Existing V2.3–V2.5 regression gates were updated to treat V2.6 as the current compatible release.

### Safety
No unrestricted exploitation, credential theft, stealth, anti-forensics, destructive actions, or real-data exfiltration capability was added.

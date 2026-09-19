# V2.7 Changelog — Expert Capability Depth

## Purpose
V2.7 follows the V2.6 maturity layer by mapping major professional pentest/red-team activities to explicit implementation states and then deepening the infrastructure assessment path.

## Added
- `modules/expert_capability_audit_v27.py`
  - 63 capability records
  - evidence-aware execution status
  - tool availability awareness
  - priority gap list
  - explicit human/restricted boundaries
- `modules/network_surface_v27.py`
  - bounded DNS/address observation
  - TLS/certificate/cipher observation with certificate verification preserved
- Pentest `dns` and `tls` phases
- DNS/TLS in default pentest and platform phase lists
- `platform --capability-audit`
- Capability audit embedded into `platform --maturity`
- V2.7 20-pass regression gate

## Correctness improvements
- Updated all specialist registry/engine versions to 2.7.
- Updated platform manifest/run version to 2.7.
- Kept V2.6 operational-maturity modules intact for backwards-compatible evidence semantics.
- Fixed the V2.7 test harness so registry bootstrapping and evidence paths are validated correctly.

## Boundaries
The audit explicitly records C2/malware, stealth/evasion, physical/social engineering and destructive operations as human/restricted areas. V2.7 does not introduce unrestricted offensive automation.

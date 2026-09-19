# V3.56 Controlled Proof Execution

## Added
- Request-bound single-use approval tokens for controlled proof execution.
- Strict scope enforcement and per-request execution guards.
- Guarded reflected-input and open-redirect proof adapters.
- V3.56 governance/catalog and regression matrix.
- Silent archive/parser skips now emit debug logging instead of being silently discarded.

## Hardened
- Fixed V37 missing `load_json` import.
- Fixed pre-test readiness version drift.
- Prevented built-in HTTP adapters from bypassing the V37 execution guard.

## Boundary
This is controlled, bounded proof execution. It does not add arbitrary shell/payload execution, credential theft, persistence, lateral movement, exfiltration, evasion, or destructive actions.

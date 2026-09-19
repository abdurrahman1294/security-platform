# V3.31.0

## Reliability & Execution Integrity Fabric

- Added `modules/reliability_execution_integrity_v331.py`.
- Added canonical preflight and global execution budgets.
- Added transactional operation state machine with strict transitions.
- Added crash/interruption recovery for in-flight operations.
- Added state integrity checks and SHA-256 state lineage digests.
- Added atomic JSON persistence with `os.replace()`.
- Added secret-field redaction including `auth_token`-style keys.
- Added structured first-class failure objects and bounded recovery policy.
- Added V3.31 regression matrix with 50 scenarios.
- Integrated V3.31 into `SecurityPlatform` and `securityctl fabric`.
- Added `tests/test_v331_reliability.py`.

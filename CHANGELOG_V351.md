# V3.51 — Safe Specialist Tool Integration Harness

- Added a disposable loopback-only integration harness for installed allowlisted tools.
- Exercises Nmap, HTTPX, Naabu, and Katana when available and passing executable-identity checks.
- Unavailable tools remain explicitly environment-limited; no generic command execution is introduced.
- Every executed tool call uses `ToolManager`, argument validation, executable identity verification, sanitized environment, bounded timeout, and the durable execution ledger.
- Added machine-readable integration evidence, readiness accounting, and regression test matrix.
- Added `specialist-tool-integration` CLI action and platform API methods.
- Extended the one-command complete campaign to include V3.51.
- Safety boundary: loopback-only, synthetic data, no credentials, no mutation, no persistence, no C2, no destructive actions.

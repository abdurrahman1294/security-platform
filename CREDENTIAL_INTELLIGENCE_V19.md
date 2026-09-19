# Credential Intelligence V1.9

The Pentest Engine now supports controlled credential discovery and verification for authorized engagements.

## Discovery
- Scans bounded engagement artifacts for credential-shaped key/value material.
- Recovers the exact value and records source/provenance and SHA-256.
- Stores raw values only in `evidence/credentials.json` with owner-only permissions.

## Verification
- Opt-in with `--verify-credentials`.
- One selected credential at a time via `--credential-id`.
- Built-in verifier is loopback/local-lab only.
- No credential spraying or reuse across unrelated services.
- Status is `valid`, `invalid`, or `unknown`; discovery alone never implies validity.

## Operator display
Use `--show-credentials` when the operator explicitly needs the recovered fake lab secret in the command output. Normal output remains redacted.

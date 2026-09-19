# V3.31 — Reliability & Execution Integrity Fabric

V3.31 hardens the V3.30 control plane. It does not introduce unrestricted
execution or new offensive primitives.

## Core guarantees

- One canonical preflight for target, scope, authorization and budgets.
- Transactional operation lifecycle: `planned → approved → started → terminal`.
- Strict transition validation prevents impossible state changes.
- Interrupted `started` operations become explicit recoverable failures.
- Global budgets cover steps, wall-clock deadline, tool attempts and concurrency.
- Canonical state receives a SHA-256 lineage digest.
- JSON artifacts use a temporary file plus `os.replace()` for atomic replacement.
- Secrets are removed from persisted state and hostile tool output cannot become
  persisted credentials.
- Duplicate operation IDs and malformed operation states are rejected.
- Scope/authorization failures block rather than trigger alternative authority.

Python documents `os.replace()` as an atomic replacement operation when the
source and destination are on the same filesystem, which is the primitive used
by the artifact writer here.

## Recovery model

A crash/interruption does not silently disappear. Any operation left in
`started` state is converted into a structured `failed` recovery record with a
retryability decision. A resumed run therefore has explicit knowledge of the
interrupted operation instead of replaying it blindly.

## Deliberate boundaries

The fabric remains delegation-only. It does not synthesize arbitrary commands,
select unrestricted exploit payloads, bypass approval, expand scope, perform
credential theft, establish persistence, propagate, exfiltrate real data, or
perform destructive impact.

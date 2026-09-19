# V3.25 — Capability Runtime

## Added
- Structured capability catalog with risk, prerequisites, perspective, objective and evidence requirements.
- Deterministic next-capability scoring and eligibility checks.
- Runtime state artifact and resumable state advancement.
- Target/perspective/objective locking and explicit authorization state.
- Bounded execution delegation to the existing V3.21 registered adapters only.
- Explicit hard-denied and high-impact runtime boundaries.
- `SecurityPlatform.capability_runtime()` API.
- CLI `fabric --action capability-runtime` and `capability-catalog`.

## Safety
V3.25 does not create new exploit primitives or grant execution authority. It preserves existing scope, authorization, ROE, approval and hard-denied controls.

# V3.24 — Universal Assessment Intelligence Layer

## Added
- Evidence-quality scoring with provenance/reproducibility/timestamp signals.
- Cross-domain correlation engine for shared assets and identities.
- State model with stale-evidence awareness.
- Competing hypothesis engine with bounded validation recommendations.
- Exposure → vulnerability → exploitability → access → privilege → objective → impact chain.
- Evidence-backed attack-path ranking; no scanner-only exploitability claims.
- Remediation/retest state tracking.
- Detection-validation planning with telemetry evidence requirements.
- Universal mission planner with explicit stop conditions.
- Professional report assembly.
- `SecurityPlatform.universal_assessment_intelligence()` API.
- CLI fabric actions for the individual intelligence layers and the full fabric.

## Safety boundary
V3.24 is an intelligence/reasoning layer. It consumes evidence and existing governed capabilities but grants no execution authority. It preserves scope, authorization, approval, kill-switch, and hard-denied autonomy controls.

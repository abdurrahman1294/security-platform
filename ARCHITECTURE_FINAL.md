# Security Platform 3.30 — Final Architecture

The platform is a governed security-assessment system composed of specialist engines plus a shared control plane. V3.30 adds the Unified Assessment Execution Fabric: a canonical state and governed lifecycle over the V3.24–V3.29 assessment, capability, personal-surface, reasoning, temporal and adversary-simulation layers.

## Core principles

1. **Scope is authoritative.** No component may expand it from discovered assets or intelligence.
2. **Authorization is explicit.** The engine never infers permission from reachability, ownership assumptions, OSINT, or an observed vulnerability.
3. **Planning is not execution.** Hypotheses and attack paths are evidence-backed planning artifacts, not proof of compromise.
4. **Execution is allowlisted.** Active generic execution is delegated to registered ToolManager adapters with hardened argv and `shell=False`.
5. **High-impact work is separately governed.** R4 procedures require exact ROE permission plus a request-bound, single-use approval token; R5 classes remain denied.
6. **Evidence is first-class.** Provenance, freshness, contradictions, source independence and temporal state affect confidence.
7. **State drift invalidates confidence.** Changes in scope, authorization, controls, identity, sessions or reachability require revalidation.
8. **Secrets are not reasoning inputs.** Secret-bearing fields are redacted from reasoning artifacts.
9. **Failure is information.** Tool failures, unavailable specialists, stale evidence and blocked branches are recorded rather than converted to success.
10. **Human judgment remains required** for novel business logic, consequential validation and final vulnerability claims.

## Capability layers

```text
V3.24 Assessment Intelligence
          ↓
V3.25 Capability Runtime
          ↓
V3.26 Personal Attack-Surface Model
          ↓
V3.27 Adversarial Reasoning
          ↓
V3.28 Temporal / Digital-Twin State
          ↓
V3.29 Unified Adversary Simulation Planner
          ↓
V3.30 Unified Assessment Execution Fabric
          ↓
Governed validation → evidence → replan → remediation → retest
```

The V3.29 planner combines these layers without bypassing their individual safety controls. It specifically looks for compound chains where several modest weaknesses combine, compares multiple authorized perspectives (including cellular IPv4/IPv6), and preserves uncertainty until fresh evidence supports a claim.

## Specialist execution boundary

```text
OSINT / Pentest / Mobile / Wireless / Cloud / Remote / Firmware / OT / Automotive / Source
                                  ↓
                         shared evidence fabric
                                  ↓
                    V3.29 reasoning + campaign plan
                                  ↓
                    V3.30 canonical execution state
                                  ↓
                 registered bounded execution only
```

Specialist-only or high-impact procedures remain delegated/governed rather than synthesized by the planner.

## Release verification

- Python compilation: PASS
- Full pytest suite: PASS
- V3.30 direct CLI plan: PASS
- V3.29 adversarial suite: 30 scenarios
- V3.30 adversarial suite: 36 scenarios
- R4 approval token reuse test: PASS
- Secret redaction and malformed-input tests: PASS

## V3.31 Reliability & Execution Integrity

V3.31 is the reliability boundary around V3.30. The canonical state is treated as transactional control-plane data rather than an informal collection of dictionaries. Operations have strict lifecycle transitions, global budgets, target/scope/authorization preflight, crash recovery, and lineage digests. Persisted JSON is atomically replaced and secret fields are removed before persistence. Failures remain first-class and determine bounded recovery or operator intervention.

Execution remains delegated to previously registered bounded capabilities; this layer cannot grant authority, expand scope, synthesize unrestricted commands, or bypass approval.

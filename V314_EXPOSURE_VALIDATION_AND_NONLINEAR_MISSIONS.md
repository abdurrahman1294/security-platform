# V3.14 — Exposure Validation & Nonlinear Mission Fabric

V3.14 is the next capability layer after the governed V3.13 execution fabric. It incorporates stronger patterns identified in current open-source research and commercial security-validation platforms without copying proprietary implementations.

## Added

- **Nonlinear branch search**: competing assessment hypotheses are retained so ambiguous failures do not force a single depth-first path.
- **Persistent clue graph**: observations, supporting/contradicting clues and provenance survive across mission steps.
- **Failure-oriented review**: transient failures can be retried; missing prerequisites, blocked controls and unknown failures can cause branch switching; scope/authorization failures never auto-retry.
- **Exposure validation**: distinguishes validated exploitation, behavioral reachability, control-blocked, restricted/unverified and unverified states.
- **Security-control validation**: per-technique outcomes can represent blocked, detected, missed or not exercised, with ATT&CK/TTP metadata.
- **Continuous revalidation**: asset, identity, cloud, source/runtime, control and threat-intelligence changes become triggers for bounded reassessment.
- **Remediation → retest**: validated findings produce patch/mitigate/monitor/accept-with-evidence decisions and a fresh-approval retest contract.
- **Scenario metadata ingestion**: threat/CVE/actor references can become ATT&CK-mapped validation hypotheses; the fabric does not silently generate or execute weaponized payloads.
- **Ephemeral engagement metadata**: assessment lifecycle can record disposable workspace/cleanup obligations.

## Research synthesis

The design draws on publicly documented capabilities from Strix, PentestGPT, CAI, MazeRunner, ATOBench, NodeZero, Pentera, Picus, AttackIQ, Bishop Fox Cosmos, Metasploit and Cobalt Strike. The important architectural lesson is not any single tool: the strongest systems combine discovery, evidence, nonlinear reasoning, validation, attack-path context, control validation, remediation and retesting.

## Governance

V3.14 does not bypass V3.13. Active execution remains governed by authorization, authoritative scope, ROE, ToolManager, exact-action approval and evidence integrity. A reasoning result never grants permission to execute an action.

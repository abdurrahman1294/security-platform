# V3.76 — Evidence Truth Layer

V3.76 closes a semantic gap found during the V3.75 live validation. A successful process exit is no longer treated as proof that useful security evidence exists.

## Truth model

- **execution_status** — whether the registered action executed successfully.
- **evidence_status** — `verified` only when the action creates or changes a non-empty evidence artifact.
- **evidence_produced** — derived from evidence verification, never from exit code alone.
- **evidence_artifacts** — exact artifacts created or changed by the action.
- **successful_executions** — execution success telemetry.
- **evidence_producing_actions** — actions that actually produced verified evidence.

## Consequence

An action can now be:

`EXECUTED SUCCESSFULLY → NO USABLE EVIDENCE`

without being promoted into the evidence set or increasing information gain. This prevents empty scanner output, skipped work, and other successful-but-uninformative calls from inflating convergence.

## Governance

The change does not add arbitrary execution authority. Registered entrypoints, authorization, scope ownership, approval gates, and the existing no-arbitrary-shell boundary remain intact.

## Validation

The V3.76 regression tests cover both sides of the boundary:

1. zero exit code + empty output + no artifact → no evidence;
2. zero exit code + non-empty artifact created by the action → verified evidence.

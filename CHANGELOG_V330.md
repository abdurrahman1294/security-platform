# V3.30.0 — Unified Assessment Execution Fabric

## Added
- Canonical assessment state for assets, evidence, hypotheses, perspectives, timeline, capabilities, failures, remediation and completion state.
- Unified discover → correlate → hypothesize → approve → validate → replan → remediate → retest → report lifecycle.
- Evidence quality and independent-source accounting.
- First-class failure classification and bounded retry/replan guidance.
- Resume-aware execution planning with target/scope/authorization locks.
- Remediation-to-retest regression planning.
- 36 adversarial control-plane scenarios.

## Hardening
- Integration layer never synthesizes new execution capabilities.
- Execution is delegation-only to existing governed runtimes.
- Secret-bearing fields are removed before artifact persistence.
- Authorization is never inferred from target identity or previous state.
- Scope cannot be expanded by the planner.
- Hypotheses never become compromise claims without evidence.

## Verification
- Full pytest suite and V3.30 focused suite must pass before release packaging.

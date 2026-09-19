# V3.43 Complete Testing Lab

V3.43 introduces a single-command deterministic testing campaign for the complete capability taxonomy. It creates synthetic vulnerability fixtures, runs every capability contract through the canonical lifecycle, records evidence/validation state, and produces a gap register.

## One command

```bash
python -m security_platform fabric --client lab --target 127.0.0.1 --output-dir ./artifacts/v343-lab --action complete-testing-lab
```

The command is local and deterministic. Dangerous capabilities use the existing lab-simulation envelope; no credential theft, persistence deployment, covert C2, destructive impact, real exfiltration, uncontrolled propagation, or arbitrary remote execution occurs.

## Outputs

- `evidence/complete-lab-report-v343.json` — complete campaign result
- `evidence/complete-lab-gap-register-v343.json` — actionable failures/gaps
- `fixtures/` — synthetic per-capability vulnerability fixtures
- capability simulation evidence for dangerous classes

## Interpretation

A passing contract means the engine can represent, govern, execute/simulate, evidence, validate, and report the capability through the current architecture. It does **not** by itself prove that an external specialist tool can exploit a real vulnerability. Specialist integration and real-tool effectiveness remain separate isolated tests.

## Single test campaign

The catalog is generated directly from `CAPABILITY_FAMILIES`, so new capabilities automatically become lab scenarios. This prevents a capability from being added without a corresponding test entry.

## Full one-command campaign

From the repository root:

```bash
python tools/run_complete_test_campaign.py
```

This runs compilation, the complete pytest regression suite, all 116 synthetic capability-lab scenarios, the V3.43 lab-suite contract matrix, and the production self-security audit. It writes one `complete-test-campaign-summary.json` plus all detailed lab evidence.

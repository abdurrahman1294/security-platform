# V33–V35 — Controlled Proof Adapter Architecture

## V33 — Proof Adapter Registry
Adds a registry of narrowly scoped, non-destructive proof adapters. Adapters are selected from normalized finding metadata and expose no arbitrary command or payload execution.

Built-in adapters:
- `http-reflection-marker` — harmless marker reflection check.
- `http-open-redirect` — redirect destination check without following redirects.

## V34 — Proof Safety Policy
Central policy limits requests/body size and explicitly rejects state change, file writes, command execution, credential access, persistence, lateral movement, and exfiltration.

## V35 — Controlled Proof Planner
Builds an operator-facing plan showing which safe adapter could be used for each finding and why an item is blocked or ready for review. Planning does not execute testing.

Artifacts:
- `evidence/proof-adapters.json`
- `evidence/controlled-proof-plan.json`
- `reports/controlled-proof-plan.md`

The existing V30 execution path remains approval-gated and bounded. V33–V35 make the proof layer modular rather than turning the framework into an unrestricted exploit runner.

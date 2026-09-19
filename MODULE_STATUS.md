# Module Status — V232 Audit Baseline

This document is the current source of truth for module maturity. Versioned
README files describe history only.

## Status model

- **Operational** — reads engagement inputs and produces target/evidence-dependent results.
- **Policy/definition** — intentionally defines a reusable policy/catalog; it is not itself a scanner.
- **Planner** — produces an evidence-dependent plan or decision queue.
- **Adapter** — controlled interface to an external tool or proof mechanism.
- **Historical** — retained only for compatibility/history and not part of the preferred execution path.

## Important rule

A module name or generated artifact is not treated as proof that a capability was
executed. Capability claims require observed inputs, outputs, provenance and, where
applicable, a real tool execution record.

## Preferred execution paths

1. `orchestrator.py` → central authorization/scope gate.
2. Registered tools → `ToolManager` → executable identity + argument policy + minimized environment.
3. Findings → shared `findings_io` → normalization/correlation/validation/reporting.
4. Controlled proof → V33 registry → V34 policy → V37 guard → safe adapter.
5. AD read-only → V228 → NetExec registered-tool policy.
6. AWS read-only → V229 fixed command set + account allowlist + caller-account verification.

## Policy modules

Some modules remain deliberately policy/catalog oriented (for example recovery
source catalogs and command-generation documentation). They must not be described
as autonomous operational capabilities. The audit tooling records this distinction.

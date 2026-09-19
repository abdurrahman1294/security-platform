# V3.62 — Exploitation Loop & Benchmark Fabric

## Objective

Close the remaining exploitation-reasoning gap by moving from a static exploit
catalog to a deterministic, convergent exploitation loop with measurable local
benchmarks.

## Added

- 13 exploitation classes covering major web/API and selected host/cloud proof families.
- Evidence-ranked candidate generation.
- Deterministic candidate identity.
- Completed-candidate convergence and revisit suppression.
- Explicit prerequisites for consequential classes.
- Source-analysis correlation helper for Python and high-signal sink patterns.
- Local benchmark scoring by class and overall success rate.
- PentestEngine `exploitation-loop` phase.
- Regression tests for determinism, governance, source analysis and benchmark scoring.

## Safety boundary

No unrestricted arbitrary shell, credential theft, persistence, lateral movement,
exfiltration or destructive execution was added. V3.62 generates and ranks proof
work; existing authorization, scope, approval and specialist execution boundaries
remain authoritative.

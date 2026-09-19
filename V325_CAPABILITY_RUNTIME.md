# V3.25 — Governed Capability Runtime

V3.25 adds a runtime decision layer above the V3.24 assessment-intelligence model. It represents available capabilities as structured records with prerequisites, risk class, supported perspectives, objective tags, evidence inputs, and value. It selects the safest/highest-value eligible next capability and can advance its state after results.

## Runtime contract
- Target and perspective are locked into every decision.
- Authorization is a prerequisite for active execution, never inferred from evidence.
- Prerequisites are explicit; blocked capabilities are not silently skipped.
- R0-R2 bounded execution delegates only to the existing registered runner.
- R4/R5 and hard-denied classes remain unavailable to autonomous runtime selection.
- No arbitrary command generation, exploit synthesis, credential theft, persistence, evasion, propagation, exfiltration, or destructive execution is added.

## CLI

`python securityctl.py fabric --action capability-catalog --client demo --target 127.0.0.1 --output-dir output/v325`

`python securityctl.py fabric --action capability-runtime --client demo --target 127.0.0.1 --output-dir output/v325 --objective full-assessment --perspective internet_ipv4 --max-steps 8`

For bounded execution, the existing scope file and authorization gate remain required:

`python securityctl.py fabric --action capability-runtime --client demo --target 127.0.0.1 --output-dir output/v325 --scope config/scope.example.txt --objective full-assessment --perspective internet_ipv4 --authorize --execute --max-steps 1`

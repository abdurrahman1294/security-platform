# V3.44 — Realistic Vulnerability Validation Laboratory

- Added 14 disposable local vulnerability scenarios spanning web/API, source/supply-chain, cloud, identity, endpoint, mobile, embedded, reverse engineering and network domains.
- Added isolated dynamic HTTP fixture bound only to loopback and an ephemeral port.
- Added static/configuration vulnerability fixtures and deterministic detectors.
- Added hidden ground-truth manifest and post-run comparison: true positive, miss, false positive.
- Added unified realistic campaign report and gap register.
- Added CLI actions: `realistic-vulnerability-lab`, `realistic-vulnerability-campaign`, `realistic-vulnerability-lab-suite`.
- No external targets, real credentials, destructive behavior, persistence, covert C2, real exfiltration, or arbitrary remote execution.
- Expanded the one-command campaign to include the realistic vulnerability validation campaign automatically.

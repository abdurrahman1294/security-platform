# Engine Audit — V3.35

The V3.32–V3.35 assurance stack was reviewed as a control-plane and evidence-quality expansion, not as a claim that every specialist domain has equivalent execution depth.

## Verified controls
- Coverage is explicit across the universal attack-surface and perspective taxonomies.
- Unknown coverage inputs remain visible instead of being silently discarded.
- Empty coverage is `null`/not-applicable rather than falsely reported as complete.
- Validation levels are monotonic and evidence-backed.
- Impact validation is separated from vulnerability/validation evidence.
- Reports preserve unconfirmed claims and limitations.
- Self-security scanning is audit-only and target-independent.
- Existing governed execution boundaries remain unchanged.

## Hardening applied
- V3.21 attempted/succeeded accounting corrected.
- V3.21 global deadline corrected.
- Multiple same-type assets now produce many-to-many dependency edges in V3.26/V3.27.
- V3.27 evidence correlation expanded beyond node-ID token overlap.
- V3.28 temporal windows require chain-relevant state transitions.

## Known architectural boundary
Legacy specialist adapters may still contain direct fixed `subprocess.run` calls. They are not granted arbitrary shell capability by this release. Full migration into ToolManager remains a reliability/self-security backlog item.

## Governance
No new unrestricted RCE, credential theft, persistence, covert C2, propagation, destructive impact, real exfiltration, carrier bypass, or uncontrolled payload generation is introduced.

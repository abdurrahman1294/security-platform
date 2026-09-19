# V3.32–V3.35 Assurance Stack

## V3.32 — Universal Coverage & Capability Assurance
- Machine-readable coverage across the 35-surface taxonomy and 14 perspectives.
- Capability/runtime and registered-adapter accounting.
- Explicit specialist/artifact gaps.
- Unknown surfaces/perspectives are preserved as input errors.
- Coverage no longer treats an empty set as 100% coverage.

## V3.33 — Validation Assurance
- Evidence-qualified claim levels: candidate → observed → supported → validated → impact-validated.
- Freshness, provenance, reproducibility, corroboration and source independence affect proof quality.
- Scanner output and hypotheses cannot self-upgrade into validated compromise.
- Impact claims require separate impact evidence.

## V3.34 — Evidence & Professional Reporting
- Evidence-faithful machine-readable reporting.
- Finding/evidence/remediation/retest linkage.
- Unconfirmed candidates remain explicitly unconfirmed.
- Limitations and governance statements are preserved.

## V3.35 — Engine Self-Security
- Static source-tree self-audit for unsafe OS execution, shell=True, dynamic code, and secret-like literals.
- Bounded file scanning with symlink/size exclusions.
- Audit is read-only and does not touch target systems or grant execution authority.

## Cross-version hardening
- V3.21 coverage now distinguishes attempted, executed and successful steps.
- V3.21 uses a true global timeout budget and preserves invalid surface requests.
- V3.26/V3.27 dependency graphs now support multiple assets of the same type.
- V3.27 evidence-to-chain correlation includes asset/type/surface context.
- V3.28 temporal windows are restricted to transitions touching chain-relevant state.

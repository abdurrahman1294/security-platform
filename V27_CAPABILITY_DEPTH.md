# V2.7 — Expert Capability Depth

V2.7 turns the previous maturity report into an explicit expert capability audit and deepens the infrastructure layer.

## New
- 63-item expert capability catalog spanning pre-engagement, reconnaissance, web/API, infrastructure, Windows/AD, cloud, mobile/wireless, remote/red-team, analysis and reporting.
- Every capability is classified as executed-evidence-backed, implemented-not-executed, implemented-but-tool-missing, lab-only, human-required, or gap.
- Priority gaps are emitted instead of hiding limitations behind a single score.
- DNS/address observation using bounded standard-library resolution.
- TLS observation with certificate verification preserved; certificate failures are recorded rather than bypassed.
- Pentest defaults now include DNS and TLS phases.
- Platform maturity now embeds the expert capability audit.

## Important interpretation
The maturity score is a coverage indicator, not a claim that the platform can replace an expert operator. Human judgment, novel vulnerability research, physical/social operations, unrestricted C2/evasion and destructive activity remain explicitly separated.

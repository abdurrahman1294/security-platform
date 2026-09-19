# V233-V240 — OSINT & Bug-Bounty Excellence

## OSINT
`--osint` builds the investigation plan and evidence model. `--osint-collect` performs only bounded public metadata collection. `--osint-input FILE` can be repeated to ingest outputs from operator-selected OSINT tools. JSON, JSONL/NDJSON, CSV, TSV and TXT are supported.

The pipeline is:
`discover -> normalize -> correlate -> confidence -> gap analysis -> intelligence report`.

Tool outputs are not trusted merely because they came from a scanner. Cross-source corroboration is required for high-confidence claims.

## Bug bounty
`--intelligence-mode bugbounty` builds program policy, adaptive test planning and quality gates. `--bounty-execute` is a separate explicit opt-in and requires `--program-policy`; the policy's scope is converted into a temporary engagement scope and the existing global authorization gate still applies before active testing.

Coverage includes reconnaissance, identity, authentication, session management, authorization, API security, business logic, client-side behavior, deployment/configuration and cloud exposure.

## Separation
Device tracking/recovery is not part of the pentest engine. A separate package is supplied for that project.

## V241-V242 Final Excellence

The final release adds two last-mile layers:

- **V241 Research Exhaustion** — converts accumulated evidence into a bounded, resumable investigation queue and explicitly surfaces remaining blind spots instead of stopping after the first scanner pass.
- **V242 Final Reality/Readiness Gate** — distinguishes code/test quality, installed tool capability, evidence completeness, and assessment readiness. It never interprets a clean scanner result as proof of a vulnerability-free target.

`--final-excellence` is the one-command end-to-end mode. It implies the complete authorized assessment path and then generates the V241-V242 final gates. Active execution still requires the normal authorization and scope controls.

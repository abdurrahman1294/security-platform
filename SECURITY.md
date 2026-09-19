# Security Model

This framework is intended for authorized security assessments and labs.

## Safety controls

- A non-empty scope allowlist is mandatory for active testing.
- The authorization gate runs before reconnaissance, port scanning, web/API scanning, authenticated scanning, screenshots, and other active phases.
- Discovered subdomains are filtered through the same allowlist before probing.
- Client names are sanitized before being used as filesystem paths.
- Session cookies/JWTs are not written into generated session reports.
- HTML report fields derived from scanner output are escaped.
- Raw HTTP request/response evidence is disabled by default; enable it only when the engagement requires it.
- Legacy shell scripts were removed because they could bypass the Python orchestrator's central safety controls.

## Secrets

Avoid passing credentials on the command line because they can be visible in process listings and shell history. Prefer environment variables or an external secret manager.

Credential files remain highly sensitive. Do not commit engagement output to Git.

## Important limitation

Scope controls reduce accidental out-of-scope testing; they are not proof of authorization. The operator remains responsible for verifying the written rules of engagement, target ownership, exclusions, rate limits, and testing window.


## Controlled Validation

Controlled Validation Mode is intentionally bounded to finding-specific, operator-approved, scope-checked observations. The current implementation uses HTTP HEAD/TLS observations where applicable and treats impact validation as a documentation gate. It is not an exploitation or post-exploitation engine.

# Final Review / Hardening — 1.4.0

This release is a correction and consistency pass rather than a feature-count release.

Highlights:
- unified active/passive preflight semantics;
- fail-closed bug-bounty policy scope and exclusion enforcement;
- tamper-evident, schema-checked cross-engine handoffs;
- public OSINT SSRF/local-target protection;
- stricter external-tool argument validation;
- AWS read-only execution moved into the shared tool boundary;
- redaction and remote-AI data handling strengthened;
- legacy HTTP observation path consolidated on the bounded HTTP helper;
- atomic credential-state writes;
- version metadata synchronized.

Verification: 111 tests passed; 196/196 application modules imported successfully; compileall passed.

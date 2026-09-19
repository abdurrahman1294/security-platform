# Final Architecture Review — 1.4.0

## Scope of review

This pass reviewed the shared platform core, specialist-engine boundaries, scope/authorization handling, cross-engine handoffs, external-tool execution, public OSINT collection, bug-bounty policy handling, AWS/AD execution paths, legacy compatibility paths, evidence handling, and static/runtime quality gates.

## Corrections made

- ScopePolicy no longer terminates the process with `SystemExit`; library callers receive structured `ValueError` failures.
- Passive OSINT and bug-bounty planning no longer inherit the active pentest scope preflight requirement.
- Platform orchestration continues independent specialists when one active specialist is blocked by scope/policy.
- Bug-bounty candidate assets can no longer expand the authoritative program scope.
- Bug-bounty active execution now checks both program scope and exclusions before requesting operator authorization.
- Handoff producer names are validated; schema version is verified; SHA-256 comparison uses constant-time comparison.
- Public OSINT collection rejects local/private/link-local/reserved/loopback targets and hostnames that cannot be safely resolved before target-host collection.
- Nuclei template path traversal is rejected.
- Nmap port specifications are validated.
- AWS read-only commands are routed through the shared allowlisted tool manager instead of direct subprocess execution.
- AI reasoning context is redacted before optional remote provider transmission; remote AI provider URLs must use HTTPS.
- Session observation uses the shared bounded non-redirecting HTTP helper.
- Credential ledger writes are atomic and malformed state is handled through the shared JSON loader.
- Specialist and package versions were synchronized to 1.4.0/1.1 where appropriate.

## Intentional boundaries

The legacy `orchestrator.py` remains for backward compatibility, but active external tool execution is routed through the central ToolManager. Historical modules retain some broad exception handling where they are defensive wrappers around optional/legacy behavior; these are not used as a substitute for the core safety boundary.

The platform does not claim vulnerability-free results. Business logic, novel vulnerabilities, and consequential validation remain areas for human review. OWASP's current WSTG explicitly recommends combining automated breadth with contextual testing and notes that business-logic testing relies on tester creativity and application knowledge. HackerOne's current Code of Conduct requires human validation before hackbot-generated findings are submitted.

## Final verification

- Syntax/compile review: PASS
- Full automated test suite: PASS
- Module import audit: PASS (196/196)
- Platform specialist discovery: PASS
- Passive OSINT without scope: PASS
- Bounty planning without active execution: PASS
- Active preflight missing-scope rejection: PASS
- Handoff tamper/schema checks: PASS
- Tool argument hardening checks: PASS
- AWS tool-boundary checks: PASS

## Status

The codebase is structurally hardened and internally consistent for the current architecture. The remaining proof required for production confidence is empirical execution against authorized, intentionally vulnerable labs with the real external toolchain installed.

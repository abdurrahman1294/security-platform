# Security Platform Architecture Refactor V2

## Final target architecture

This repository is now organized as one **Security Platform** containing three independently executable specialist engines:

- **Pentest Engine** — authorized technical assessment.
- **OSINT Engine** — public-source intelligence research and correlation.
- **Bug Bounty Engine** — program-policy-aware vulnerability research and triage.

They share infrastructure, not methodology.

```text
                    SECURITY PLATFORM
                           |
             +-------------+-------------+
             |             |             |
           OSINT         PENTEST       BOUNTY
          specialist    specialist    specialist
             |             |             |
             +-------------+-------------+
                           |
                      SHARED CORE
                           |
       scope / authorization / tools / state / evidence
       provenance / artifacts / schemas / reporting
```

## Independence

Each engine has its own CLI command and workflow. A handoff from one engine is only **untrusted structured intelligence**. A consuming engine must independently enforce its own authorization and scope policy.

## Coordination

`securityctl platform` is an optional coordinator. It does not merge methodologies or authority. It simply runs selected specialists and records a platform-level result.

## Migration principle

The original V242 implementation is retained as the compatibility/reference layer while capabilities are progressively moved behind specialist boundaries. New functionality should be added to the correct specialist or shared core rather than to a monolithic orchestrator.

## Operational truth

The platform is designed for maximum useful automation, not a claim of perfect vulnerability discovery. OWASP notes that business-logic abuse testing requires application context and human creativity; HackerOne likewise requires human validation of potential hackbot findings before submission. The bounty engine therefore stops at research/triage/readiness unless an authorized operator explicitly initiates active testing.

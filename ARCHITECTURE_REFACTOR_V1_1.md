# Architecture Refactor V1.1

This phase establishes the platform boundary without duplicating the existing security modules.

## Specialist engines

- `PentestEngine`: authorized technical assessment workflow.
- `OSINTEngine`: public-source intelligence workflow.
- `BugBountyEngine`: program-aware bounty research workflow.

## Shared core

The shared core owns only cross-cutting infrastructure: engagement identity, scope policy, tool inventory/execution, artifact persistence, structured handoffs, engine contracts, registry and platform manifest.

## Independence rule

An engine may consume another engine's artifacts only as untrusted intelligence. The consuming engine must independently enforce its own scope and authorization requirements before any active action.

## CLI

```text
securityctl engines
securityctl tools
securityctl pentest ...
securityctl osint ...
securityctl bounty ...
```

Bug bounty planning remains non-active. `bounty --execute` is an explicit active request and still requires the global authorization gate.

## Next migration boundary

The next work should move existing pentest capabilities behind the PentestEngine facade, make bounty execution a complete policy -> plan -> authorized execution -> evidence -> triage workflow, and make OSINT collection/correlation independently resumable. No large feature additions should be made until those workflows pass end-to-end lab tests.

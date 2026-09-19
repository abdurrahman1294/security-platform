# Architecture Refactor — Security Platform v1.0.0

## Decision

The former all-in-one orchestrator is now being transitioned into a **platform + specialist-engine architecture**:

1. **Pentest Engine** — authorized technical security assessment.
2. **Bug Bounty Engine** — program-policy-aware research, prioritization and triage.
3. **OSINT Engine** — passive public-source collection, normalization, correlation and intelligence.
4. **Shared Core** — scope, engagement state, tool execution, evidence/artifacts and controlled handoffs.

The legacy `orchestrator.py` remains as a compatibility runner during the migration. It is not the architectural center of the new platform.

## Why this is the final direction

Pentesting, bug bounty research and OSINT have overlapping capabilities but different objectives and control loops. A specialist boundary makes each workflow independently testable and usable while preventing duplicated security-critical infrastructure.

The separation also matches current security-testing guidance: automation provides breadth, while human judgment remains important for context and business logic. OWASP's current WSTG explicitly describes automated tools as valuable but insufficient on their own and highlights business-logic testing as an area requiring contextual reasoning. HackerOne's current guidance likewise requires human validation for hackbot-generated findings before submission. 

## Cross-engine rule

An engine may publish structured intelligence, but **an intelligence handoff never grants authorization**. Any active engine re-applies its own scope and authorization controls.

OSINT currently publishes a local `handoff-osint.json` containing normalized asset candidates. Pentest may consume those candidates only after its own scope and authorization gates pass.

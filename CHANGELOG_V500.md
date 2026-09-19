# V5.0 — Capability Fusion

## Added
- Large external security-tool capability catalog (metadata-only until locally registered).
- Specialist agent catalog spanning recon, web/API, identity, network, cloud, binary, forensics, OSINT, source, CVE, validation and reporting.
- Deterministic adaptive tool selection using objective, evidence, novelty and prior failures.
- Durable SQLite task leasing, execution receipts and coverage state.
- Provider/model routing metadata for hosted and local models.
- MCP-compatible JSON-RPC inspection and governed planning bridge.
- Governance-aware registered-adapter execution path with authorization, scope and approval gates.
- Convergence controls and explicit catalog-vs-installed distinction.
- Attribution and provenance documentation.

## Design
V5.0 absorbs documented capabilities from HexStrike AI and PentestGPT at the
architecture/behavior level without copying their source code. The existing
platform remains authoritative for scope, authorization and execution.

# V3.4 Platform Depth Pass

V3.4 focuses on making the platform more coherent rather than claiming unsupported offensive capability.

## Added

- normalized attack-surface inventory from existing exports
- bounded evidence-driven mission planner
- evidence provenance/hash inventory
- deterministic snapshot retest comparison
- evidence-backed report pack
- EngagementRunner integration and resume support
- `securityctl mission` planning command
- capability-audit entries for the new platform services

## Safety boundary

Planning, normalization, correlation, reporting and retest comparison do not grant authority or execute consequential actions. Existing proof/exploitation adapters remain independently gated by scope, ROE and operator approval.

Novel zero-day discovery, malware/C2 operations, stealth/evasion, physical/social engineering and destructive actions remain outside automatic execution.

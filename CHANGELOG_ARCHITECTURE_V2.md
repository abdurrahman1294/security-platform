# Architecture V2 — Final Consolidation Pass

- Promoted OSINT to an active independent specialist engine.
- Added capability metadata and versions to the engine registry.
- Added `securityctl platform` multi-engine coordinator.
- Added standardized platform run artifact: `platform-run.json`.
- Strengthened the shared-core authority boundary: cross-engine handoffs cannot grant permission.
- Standardized Pentest engine results through `EngineResult`.
- Added architecture-level tests for specialist capabilities and authority boundaries.
- Removed temporary files and Python cache artifacts from the distributable tree.
- Preserved the legacy orchestrator for compatibility while specialist migration continues.
- No automatic bounty submission and no automatic scope expansion.

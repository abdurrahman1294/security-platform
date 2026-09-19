# Architecture Refactor V1.1

- Added stable `EngineContext`, `EngineResult`, and `EngineContract` contracts.
- Added specialist engine registry.
- Added `SecurityPlatform` coordinator and platform manifest.
- Added independent `engines`, `tools`, `pentest`, `osint`, and `bounty` CLI surfaces.
- Added explicit `--execute` bounty control while retaining authorization enforcement.
- Added architecture and registry tests.
- Preserved the V242 compatibility orchestrator during migration.

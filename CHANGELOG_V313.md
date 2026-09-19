# Changelog — V3.13

## Governed Mission Fabric

V3.13 adds the governed execution layer on top of the V3.12 adaptive controller.

### Added
- Workflow coverage matrix for major Metasploit/Cobalt Strike-style assessment/red-team workflows.
- Bounded governed mission plan derived from adaptive specialist selection.
- Exact-action, exact-target approval requests.
- Single-use approval-token enforcement for active mission actions.
- Authorization and scope re-check immediately before execution.
- Durable plan, request, coverage and execution artifacts.
- Platform-level `governed_mission_fabric()` integration.
- `securityctl fabric` actions: `coverage`, `mission-plan`, `request-approvals`, `execute`.
- Ten focused V3.13 tests.

### Safety/governance
- Active execution remains behind the existing ToolManager/HardenedToolExecutor boundary.
- No alternate shell or arbitrary command execution path was added.
- No automatic payload generation, C2, stealth/evasion, credential capture/theft, persistence deployment, or destructive execution was added.
- Those categories are explicitly represented as external-specialist, lab-only, or denied coverage rather than falsely marked as implemented.

### Validation
- V3.13 focused tests: 10 passed.
- Full repository test suite: all tests passed.

# V3.55.0

## Pre-test readiness gate

Adds a deterministic readiness gate that runs before the engine validation campaign. It verifies Python/dependency availability, core imports, repository layout, version consistency, artifact write access, loopback availability, external-target guardrails, and specialist-tool inventory.

The gate is preparation only: it does not test targets, execute offensive actions, or contact external systems. The complete campaign now aborts before tests if hard readiness checks fail.

Also fixes the `specialist-isolated-range` CLI parser so `--no-execute` is explicitly defined before dispatch.

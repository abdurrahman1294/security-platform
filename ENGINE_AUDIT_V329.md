# V3.29 Engine Audit

## Scope

Reviewed the V3.24–V3.29 reasoning/capability layers, CLI integration, execution boundary, approval controls, version metadata, syntax/import health, and regression behavior.

## Findings and corrections

### 1. R4 approval token was not actually single-use — FIXED

The V3.22 R4 executor previously accepted any non-empty approval token. The durable approval queue already supported exact request/action/target matching and consumption, but the R4 path did not call it. This created a governance inconsistency: the interface described single-use approval while the executor only checked presence.

**Correction:** R4 execution now requires `request_id=token`, validates the token against the durable queue, and consumes it before lab execution. Reuse is rejected.

### 2. V3.29 temporal ordering could mis-order mixed timestamp representations — FIXED

The new planner initially sorted timeline timestamps lexicographically. Numeric timestamps such as `9` and `10` can be ordered incorrectly as strings. The planner now derives a numeric ordering value with a deterministic input-index fallback.

### 3. V3.29 was initially only a wrapper around supplied chains — FIXED

A true unified layer should reuse prior reasoning/capability layers rather than merely rename their output. V3.29 now derives V3.27 chains when no chains are supplied, checks V3.25 capability availability, previews V3.24 attack-path intelligence, and incorporates V3.28 temporal reasoning metadata.

### 4. Documentation had fallen behind the implementation — FIXED

The previous final architecture described an older three-engine architecture and did not represent V3.24–V3.29. It has been replaced with a current layered architecture and explicit invariants.

## Intentional limitations / non-bugs

- The planner does not claim that a hypothesis is a compromise. This is deliberate evidence discipline.
- Specialist-required domains are not silently converted into generic command execution.
- Cellular perspective is a vantage point, not a bypass around carrier or network controls.
- Payload assurance remains limited to bounded benign proofs; unrestricted weaponized payload generation is not part of the engine.
- Empty coverage is represented as a valid state rather than a crash.
- Optional tools being unavailable are recorded as blocked/limited execution rather than treated as findings.

## Verification

- Full pytest suite: **PASS**
- Python compileall: **PASS**
- V3.29 CLI plan: **PASS**
- V3.29 adversarial test matrix: **30 scenarios**
- R4 request-bound single-use regression: **PASS**
- No duplicate platform methods detected.
- CLI action choice sets are unique.
- No `shell=True` or `os.system()` execution path found in the governed tool manager.

## Remaining engineering risks

1. Empirical coverage still depends on the actual external security tools being installed and their output formats.
2. Business-logic vulnerabilities cannot be fully automated without contextual human judgment.
3. Some legacy modules intentionally retain defensive broad exception handling; they are not substitutes for the central execution boundary.
4. The engine should continue to receive fixture-based tests for every new adapter and provider-output format.

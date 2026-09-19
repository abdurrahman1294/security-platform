# Engine Audit — V3.31

## Scope

The V3.30 unified execution layer was reviewed for reliability, resumability,
state integrity, budget enforcement, and artifact durability.

## Findings addressed

1. **No single global budget contract** — V3.31 adds step, wall-clock, tool and
   concurrency budgets.
2. **In-flight execution could be ambiguous after interruption** — V3.31
   converts interrupted `started` operations into explicit recoverable failures.
3. **Operation transitions were implicit** — V3.31 validates every transition.
4. **Artifact replacement needed a crash-safe primitive** — V3.31 uses a
   temporary file, flush/fsync, and `os.replace()`.
5. **State lineage was not explicit** — V3.31 records a canonical SHA-256 digest.
6. **Secret filtering needed broader matching** — V3.31 includes token/auth-token
   and related variants.
7. **Duplicate operation IDs could corrupt resumability** — V3.31 detects them.

## Verification target

- Full pytest suite.
- Python compilation.
- V3.31 dedicated regression tests.
- CLI suite and direct V3.31 execution.
- Archive integrity.

## Residual hardening backlog

- Migrate remaining historical direct subprocess adapters to ToolManager.
- Continue replacing historical non-atomic evidence writers.
- Add process-level fault injection and filesystem power-loss simulation where
  practical.
- Benchmark multi-process ledger contention before enabling higher concurrency.

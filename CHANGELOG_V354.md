# V3.54.0

## Added
- Disposable isolated specialist assessment range across 16 domains.
- Loopback HTTP and TCP services with ephemeral ports.
- Domain-specific target artifacts for Linux, Windows/AD, cloud, Kubernetes, Android, iOS, wireless, firmware, OT/ICS, automotive, reverse engineering, source/CI, data, and AI/ML.
- Interface-first discovery and separate hidden ground truth.
- Per-domain true-positive, miss, and false-positive accounting.
- Platform and CLI integration.
- Complete campaign integration and regression matrix.

## Hardened
- Raw fixture strings are written atomically without secret-redaction transformations that would alter test semantics.
- Synthetic source markers avoid secret-audit false positives while remaining detectable by the lab detector.
- Assurance stack schema advanced to 3.54.0 and includes the isolated specialist range.

## Validation
- Full pytest suite: PASS.
- compileall: PASS.
- Complete campaign: PASS.
- V3.54 isolated range: 16/16 targets, 31/31 checks, 30/30 true positives, 0 misses, 0 false positives.
- Production self-security scan: 0 high/medium/critical findings.

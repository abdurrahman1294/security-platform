# V3.54 — Isolated Specialist Assessment Range

V3.54 adds a disposable, local specialist range spanning 16 assessment domains. Each domain gets an isolated target directory or a short-lived loopback service. Discovery runs against the target interface/artifact before the hidden ground-truth manifest is written and used for scoring.

## Domains

web/API, network, Linux, Windows/AD, cloud/IAM, Kubernetes, Android, iOS, wireless, IoT/firmware, OT/ICS, automotive, reverse engineering, source/CI, data, and AI/ML.

## Guarantees

- Loopback/local only
- Ephemeral services and disposable target state
- No real credentials or secrets
- No external network targets
- No persistence, C2, propagation, destructive actions, or unrestricted remote execution
- Hidden ground truth is not used by discovery
- True-positive, miss, and false-positive accounting per domain
- Cleanup in a `finally` path
- Machine-readable evidence artifact

## Important boundary

This is a genuine executable local validation range, but it is not equivalent to a physical Windows/AD lab, real wireless radio, iOS simulator, cloud provider account, automotive CAN bus, or OT plant. Those require the corresponding specialist runtime and isolated infrastructure. V3.54 makes that boundary explicit instead of claiming synthetic coverage is real-world coverage.

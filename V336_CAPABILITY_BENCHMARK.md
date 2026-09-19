# V3.36 Capability Benchmark & Gap Audit

V3.36 benchmarks the platform at the **capability-family level** against established professional security-assessment concepts. It is deliberately not a vendor feature-parity claim.

## Reference basis

- MITRE CALDERA: automated adversary emulation and security assessment.
- MITRE Adversary Emulation Plans: ATT&CK-aligned adversary behavior modeling.
- OWASP WSTG: comprehensive web/API testing methodology.
- Metasploit: modular penetration-testing and vulnerability-validation workflows.

## Result categories

- `implemented`: strong native architecture/evidence for the family.
- `implemented-bounded`: supported with explicit safety/execution limits.
- `implemented-specialist`: specialist/testbed functionality exists, but is not universally orchestrated.
- `implemented-planning`: planning/reasoning is present; broad autonomous execution is intentionally not assumed.

## Important distinction

A registered capability, adapter, or test procedure is **not** the same thing as complete real-world coverage. V3.36 therefore reports genuine gaps rather than converting module count into a maturity claim.

## Current major gaps

1. Full enterprise endpoint-agent adversary-emulation runtime.
2. Mature broad web/API test corpus comparable to dedicated application-testing platforms.
3. Deep protocol-specific identity/post-compromise procedure depth.
4. Uniform central orchestration for every mobile/wireless specialist tool.
5. Physical/testbed execution remains specialist and lab constrained.
6. Unified fuzzing campaign/corpus/crash-triage runtime.
7. Dedicated multi-engagement datastore and analytics layer.
8. Remaining legacy subprocess boundaries outside ToolManager.

The safe architecture deliberately does **not** turn these gaps into unrestricted autonomous exploitation, credential theft, persistence, propagation, destructive impact, covert C2, or scope bypass.

## Next engineering priority

Do not add another large collection of modules immediately. Prioritize the highest-value gaps by evidence depth, reliability, and safe integration. The first candidate is a **unified capability adapter contract** that makes specialist tools produce the same canonical evidence, failure, provenance, and lifecycle records as the core engine.

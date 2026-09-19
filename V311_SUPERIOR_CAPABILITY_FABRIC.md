# V3.11 Superior Capability Fabric

V3.11 is a capability-depth release, not merely another tool catalog. It combines
higher-value patterns from modern open-source pentest/AI-security projects while
keeping the platform's authorization, scope, evidence and approval boundaries.

## What is materially stronger

### 1. Multi-role agentic planning
The platform now represents an assessment as cooperating specialist roles:
recon, web/API, source analysis, identity, cloud, mobile, network, correlator,
validator and reporter. Tasks carry dependencies, priorities, resume keys and
approval requirements. Independent work can be scheduled in bounded parallel
branches.

### 2. Source + runtime correlation
SARIF from tools such as Semgrep or CodeQL can be normalized and correlated with
runtime/web evidence. Static analysis narrows a hypothesis; runtime evidence is
still required for stronger validation.

### 3. Browser/proxy evidence fabric
HAR-like browser or proxy traces are normalized into reusable flows for
authenticated workflow mapping, API discovery, business-logic candidates and
regression baselines. Credentials are not retained by this importer.

### 4. Continuous assurance
Evidence fingerprints can be baselined and compared after changes. The platform
turns changed artifacts into bounded reassessment/retest tasks instead of treating
continuous scanning as a fresh unrestricted engagement.

### 5. Benchmark-quality measurement
The platform now records execution success rate, QA pass rate and proof metrics,
and defines benchmark dimensions such as coverage, proof rate, false-positive
rate, time-to-validated-finding, resume reliability, scope-violation rate and
evidence completeness.

## Why this is better than simply copying specialist tools

Specialists remain better at their individual jobs. The platform's advantage is
composing their evidence into one governed workflow: source evidence + runtime
flows + infrastructure + identity + cloud + mobile + attack-path context + proof
and retest + reporting.

## CLI

```text
securityctl fabric ... --action plan
securityctl fabric ... --action sarif --input results.sarif
securityctl fabric ... --action correlate --runtime-artifact browser-trace-v311.json
securityctl fabric ... --action browser-trace --input trace.har
securityctl fabric ... --action continuous --baseline previous.json
securityctl fabric ... --action benchmark
```

## Deliberate exclusions

No autonomous C2, payload generation, credential capture/theft, persistence,
evasion, relay/poisoning, destructive actions, or arbitrary shell execution was
added. Imported evidence cannot expand authorization or scope.

### 6. Provider-agnostic AI routing
The fabric adds a model-provider registry and role-aware routing policy so the
assessment logic is not hard-wired to one LLM. Local/offline providers are
supported as a first-class policy option; secrets are not stored by the fabric.

### 7. ATT&CK/emulation planning layer
ATT&CK/Atomic-style metadata can be imported as a planning and coverage source.
The platform can map techniques to assessment/detection validation work without
embedding or automatically executing adversary payloads.

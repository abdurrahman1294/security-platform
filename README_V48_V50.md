# V48–V50 Adaptive Web/API Assessment Engine

## V48 — Web/API Test Matrix
Builds a deterministic, non-destructive test matrix from the V47 assessment plan. Each case is marked for operator approval.

Artifact: `evidence/web-test-matrix-v48.json`
Report: `reports/web-test-matrix-v48.md`

## V49 — Bounded Web/API Observation Runner
Executes only tightly bounded HTTP observations against in-scope targets:
- GET only
- HTTP/HTTPS only
- no redirect following
- maximum 10 requests per run
- maximum 64 KiB response body
- no payload injection or state-changing methods
- no credential extraction or secret storage
- explicit operator approval required
- every target checked against the supplied scope

Artifact: `evidence/web-probe-v49.json`
Report: `reports/web-probe-v49.md`

## V50 — Adaptive Web/API Decisions
Correlates the V48 matrix with V49 observations and ranks the next operator review step. It does not authorize exploitation.

Artifact: `evidence/web-decisions-v50.json`
Report: `reports/web-decisions-v50.md`

## CLI

```bash
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-engine --scope-file config/scope.example.txt
```

Individual operations:

```bash
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-test-matrix
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-probe --scope-file config/scope.example.txt
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-decisions
```

`--web-engine` builds V48, asks for explicit approval before V49 observations, then builds V50 decisions.

## Lifecycle

```text
V45 Surface Model
    ↓
V46 Endpoint Intelligence
    ↓
V47 Assessment Plan
    ↓
V48 Test Matrix
    ↓
V49 Bounded Observation
    ↓
V50 Adaptive Decisions
    ↓
Controlled Validation / Proof / Evidence / Reporting
```

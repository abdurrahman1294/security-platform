# V42–V44 — Unified Assessment Pipeline

This milestone changes the framework from a mission planner into an executable, resumable assessment pipeline.

## V42 — Pipeline Graph
Creates `evidence/assessment-pipeline-v42.json` and a human-readable plan. Tasks are dependency-aware and can be resumed.

## V43 — Result Collector
Stores each task's sanitized output under `evidence/pipeline-results/`, with SHA-256 hashes and execution metadata.

## V44 — Pipeline Runner
Runs the next dependency-ready assessment action through the V40 allowlisted ToolManager. The runner does not accept arbitrary shell strings and does not bypass scope or authorization controls.

### Pipeline
`external-recon → http-probe → port-discovery → service-enumeration → web-crawl → vulnerability-discovery`

The pipeline is deliberately incremental: after each action, the result is collected and the next eligible task can be selected. Controlled validation/proof remains a separate operator-approved stage.

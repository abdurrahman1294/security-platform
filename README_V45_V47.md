# V45–V47 — Deep Web/API Assessment Engine

This milestone turns the framework's web pipeline outputs into a structured application-security model and a prioritized assessment plan.

## V45 — Web/API Surface Model

`modules/web_surface_v45.py`

Builds an artifact-derived model of:

`domains → hosts → applications → pages/endpoints → parameters → candidate vulnerabilities`

Output:
- `evidence/web-surface-v45.json`
- `reports/web-surface-v45.md`

No network activity is performed by V45.

## V46 — Endpoint Intelligence

`modules/web_endpoint_v46.py`

Normalizes and deduplicates endpoints and identifies:
- API candidates
- authentication-related routes
- sensitive/object parameters
- business-logic candidate routes
- priority parameters

Output:
- `evidence/web-endpoints-v46.json`
- `reports/web-endpoints-v46.md`

V46 is also artifact-derived and does not contact targets.

## V47 — Web/API Assessment Planner

`modules/web_assessment_v47.py`

Creates a prioritized operator-facing plan covering:
- API authorization
- input validation
- object-reference/IDOR review
- authentication/session review
- API discovery
- security configuration
- business-logic workflows

Every planned test is marked `operator_approval_required=true`. V47 is planning-only.

## CLI

Run the complete stack against an existing engagement directory:

```bash
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-assessment
```

Or run individual stages:

```bash
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-surface
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-endpoints
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --web-assessment-plan
```

The deeper web/API model is designed to feed future adaptive decisions and controlled validation/proof. It does not autonomously exploit vulnerabilities or bypass authorization.

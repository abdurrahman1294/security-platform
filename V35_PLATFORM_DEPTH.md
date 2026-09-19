# V3.5 Platform Depth

V3.5 strengthens cross-domain correlation, authenticated role-result analysis,
service/protocol coverage, and remediation lifecycle tracking.

All new modules consume existing evidence or operator-provided results. They do
not expand scope, execute exploitation, use credentials, pivot, persist, or
perform destructive actions.

## New components

- `cross_domain_attack_paths_v35.py` — bounded cross-domain hypotheses.
- `auth_role_analysis_v35.py` — multi-role authorization-result analysis.
- `service_protocol_intelligence_v35.py` — normalized service/protocol coverage.
- `remediation_tracking_v35.py` — severity-aware remediation lifecycle.

The engagement runner invokes these components as resumable phases.

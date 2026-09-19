# V3.6 Intelligence Fabric

V3.6 turns the platform into an evidence-oriented assessment loop:

`observe -> normalize -> correlate -> rank gaps -> operator review -> bounded validation -> evidence -> remediate -> retest -> diff`

## New components

- `modules/intelligence_fabric_v36.py` — conservative cross-domain evidence graph.
- `modules/adaptive_next_steps_v36.py` — evidence-gap-driven follow-up suggestions.
- `modules/continuous_diff_v36.py` — snapshot and evidence-drift comparison.

The fabric only correlates observations that share a concrete asset identifier; it no longer creates arbitrary cross-domain Cartesian pairs. Suggestions never grant authority or execute target actions.

## Safety

Authorization, scope, tool allowlists, operator approval, consequential proof, remediation, retesting and closure remain independent gates. Evidence absence or change is never treated as proof by itself.

# V3.78 Comprehensive Mission Intelligence

V3.78 consolidates the major reasoning upgrades into one governed mission layer.

## Flow

Discover → evidence normalization → hypothesis persistence → dependency analysis →
next-test ranking → governed execution → evidence verification → attack/exploitation
proof candidate → reassessment → coverage gaps → operator queue → report readiness.

## Included

- Persistent hypotheses and explicit evidence gaps.
- Evidence provenance graph; co-location never counts as corroboration.
- Hypothesis-to-exploitation bridge using existing technique classes only.
- Adaptive recovery/retry planning without blind automatic retries.
- Coverage-gap model and hypothesis-driven prioritization.
- Operator approval/prerequisite queue.
- Mission fingerprinting for resume/correlation.
- Convergence states that distinguish unresolved, blocked and converged work.
- Existing scope, authorization, approval, ToolManager and evidence gates remain authoritative.

## Deliberate boundaries

The layer does not grant authority, expand scope, execute arbitrary shell, deploy persistence,
perform credential theft, create covert C2, or turn a hypothesis into a finding without verified evidence.

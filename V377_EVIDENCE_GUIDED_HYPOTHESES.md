# V3.77 — Evidence-Guided Hypothesis Persistence & Dependency Engine

V3.77 fixes a reasoning-depth problem in V3.76: a run could stop after one useful
artifact even when the mission context contained a strong, unresolved hypothesis
whose decisive test was blocked by an explicit prerequisite.

## Core rule

**Hypothesis != finding.** Context can create and preserve a hypothesis, but only
verified evidence may support a finding.

## What changed

- Detects high-value hypotheses from objective/story context.
- Persists hypotheses across runs through `evidence/hypothesis-dependency-v377.json`.
- Tracks explicit dependencies such as authenticated session and crawled URL artifact.
- Selects the first/highest-value missing test deterministically.
- Distinguishes `converged`, `blocked_pending_evidence`, `ready_for_operator`, and `partial`.
- Reports the exact dependency that blocks the next decisive test.
- Never grants authorization, expands scope, or creates arbitrary execution paths.

## Example

A story saying that an API returns different data for two roles and behaves strangely
when object IDs change produces an **access-control hypothesis**. If the authenticated
phase is approval-gated, V3.77 reports `blocked_pending_evidence` rather than claiming
that IDOR exists.

Desired loop:

`Discover → Hypothesis → Evidence Gap → Targeted Test → Evidence → Reassess → Exploit Candidate → Validate → Report`

# V3.65 — Adaptive Offensive Brain

V3.65 makes Python the full primary capability layer while adding AI as a second method of analysis and a hybrid feedback loop.

## Three operating methods

1. **Python** — run the existing deterministic assessment capabilities at their configured maximum.
2. **AI** — ingest operator narrative, observations and evidence, form hypotheses, and select registered capabilities for governed execution.
3. **Hybrid** — Python gathers evidence first, AI reasons over it, registered tools execute the selected actions, and the resulting evidence becomes input to the next reasoning cycle.

## Operator narrative

The operator can describe observations, suspected weaknesses, application behavior, business context, unusual responses, or specific questions. The AI should treat that narrative as evidence and hypothesis input rather than as authority to bypass platform controls.

When the narrative is empty, the brain generates its own hypotheses from available evidence.

## GUI principles

The desktop UI exposes high-level capability buttons instead of an arbitrary shell. Commands remain visible for transparency. Active operations require explicit authorization acknowledgement, and execution continues through the existing scope, registered-tool, approval, evidence and audit controls.

## Engineering objective

The goal is not merely more modules. The goal is an adaptive loop:

`observe → hypothesize → select test → execute → interpret → revise → prove → report`

All claims of superiority over other systems should be established through controlled matched benchmarks, not feature counts.

# V3.64 — Tri-Modal Offensive Assessment + Operator GUI

## Three ways to work

1. **Python mode** — run the existing deterministic engine at its maximum configured capability.
2. **AI mode** — give the AI the operator's narrative and current evidence; it generates hypotheses and selects registered capabilities, then the governed executor performs eligible actions.
3. **Hybrid mode** — Python performs broad collection first, then AI reasons over the resulting evidence and feeds the next actions back to the Python execution layer.

No capability is removed from Python. AI is additive: reasoning, correlation, hypothesis generation, adaptive replanning and narrative understanding.

## Operator narrative

The AI accepts a natural-language story from the pentester: what was observed, what is suspicious, what the application is supposed to do, where an interesting workflow appears, and what the operator wants investigated. When the story is empty, the engine derives hypotheses from collected evidence.

## GUI

`gui/security_platform_gui.py` is a standard-library Tkinter desktop UI. It provides:

- engagement/client, target, scope and output fields
- narrative/context box
- authorization confirmation
- Preflight
- Python Full Assessment
- AI Reason + Test
- Hybrid Autopilot
- Exploit
- Report
- exact command preview and activity log

The GUI deliberately exposes named security capabilities rather than an arbitrary shell. A command can be displayed and audited before the button executes it.

## Governance

The AI is not the authority boundary. Execution remains subject to the existing target scope, authorization state, registered-tool allowlist, approval requirements, evidence recording and audit trail. This prevents a model mistake from becoming an uncontrolled operation while leaving its reasoning space broad.

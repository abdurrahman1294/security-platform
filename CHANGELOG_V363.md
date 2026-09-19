# V3.63 — Offensive AI Reasoning & Agent Loop

## What changed

V3.63 changes the AI from a report-writing assistant into an adaptive reasoning layer for authorized engagements.

### AI responsibilities
- attacker-style hypothesis generation
- source/runtime evidence correlation
- exploit-class selection and prioritization
- multi-step action sequencing
- interpretation of fresh tool observations
- adaptive replanning after failed or contradictory attempts
- explicit stop conditions and uncertainty handling

### Deterministic responsibilities
- scope validation
- authorization state
- approval tokens for consequential actions
- registered-tool enforcement
- structured argv only; no model-generated shell interpretation
- evidence and execution receipts
- durable engagement state

### New modules
- `modules/ai_offensive_agent_v363.py`
- `modules/agentic_executor_v363.py`
- `tests/test_v363_ai_offensive_agent.py`
- `tests/test_v363_agent_executor.py`

### New phases
- `ai-offensive`
- `ai-exploitation`
- `agentic-exploitation`
- `agent-loop`

## Design principle

The goal is not to make the model timid. The goal is to let the model reason as broadly and creatively as an expert offensive operator while preventing a language-model response from becoming authority, scope, or an arbitrary process primitive.

This is also the correct way to compare against other agentic pentesters: the model should be evaluated on attack-hypothesis quality, adaptive sequencing, proof rate, recovery, convergence, evidence quality and time-to-proof—not on how many static Python playbooks are installed.

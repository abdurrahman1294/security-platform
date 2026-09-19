# V3.67 Intelligence Upgrade

## Purpose

V3.67 turns the GUI into a persistent conversational security workspace and adds two reasoning capabilities:

1. **Autonomous Attack-Path Intelligence** — an evidence-grounded graph of assets, findings, identities, trust boundaries and candidate transitions, ranked by information gain.
2. **Rare-Case Reasoning** — case-based retrieval plus structured novel-hypothesis generation for unusual or previously unseen situations.

## Operating model

Python remains the maximum deterministic capability layer. AI remains an adaptive reasoning layer. Hybrid combines both. The intelligence layer may propose, prioritize and explain actions, but model output never directly becomes arbitrary executable code.

## Rare-case loop

`facts → constraints → analogous cases → competing hypotheses → discriminating experiment → evidence → update → newly unlocked paths`

Historical cases are treated as lessons, not proof. Novel reasoning is explicitly labeled heuristic until supported by evidence.

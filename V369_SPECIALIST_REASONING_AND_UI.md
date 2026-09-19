# V3.69 — Specialist Reasoning Loop + Operator UI Refresh

## Reasoning
V3.69 adds a specialist-to-specialist loop. Selected specialists execute only registered PentestEngine entry points. Their observations are retained as loop evidence, the specialist router is rerun, and cross-domain challenge questions are generated to encourage corroboration and contradiction rather than one-shot conclusions.

## UI
The Tkinter interface was redesigned as a dark cyber-operations workspace with:
- engagement strip and target/scope visibility;
- mission story input for non-technical users;
- Python / AI / Hybrid mode selector;
- live specialist map;
- tabbed Advisor / Attack Path / Rare Case / Specialist Loop workspace;
- action center with named capabilities;
- run telemetry and progress indicator;
- explicit governed-execution footer;
- no arbitrary shell input.

The UI is presentation-focused but remains backed by the same deterministic authorization, scope, approval, tool and evidence controls.

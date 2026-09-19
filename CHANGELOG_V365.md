# V3.65 — Adaptive Offensive Brain + Polished GUI

- Added `modules/offensive_brain_v365.py` for context aggregation and adaptive hypothesis metadata.
- Added `modules/adaptive_mission_v365.py` with Python, AI and Hybrid mission modes.
- Preserved existing Python capabilities instead of replacing them with AI.
- Hybrid mode now explicitly performs Python evidence collection before AI reasoning and records post-reasoning evidence state.
- Fixed the V3.64 hybrid controller's missing `authorized` parameter.
- Added `PentestEngine.adaptive_mission()` integration.
- Rebuilt the desktop GUI with a dark operator-oriented visual system, cards, status badge, narrative panel, mode selector, high-level action buttons and transparent command preview.
- GUI does not expose arbitrary shell execution.
- Added V3.65 architecture documentation.

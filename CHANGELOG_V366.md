# V3.66 — Cybersecurity Advisor

Added a user-facing cybersecurity decision-support layer.

## Capabilities
- Answers questions such as “is this hackable?”, “is this doable?”, “which approach is better?”, and “how should I test this?”
- Uses the operator target/engagement context when supplied.
- Provides feasibility assessment, recommended approach, decision framework, warnings, and follow-up questions.
- Supports an optional HTTPS AI reasoning provider through the existing provider seam, with deterministic offline fallback.
- Stores advice artifacts under the engagement evidence directory when an output root is supplied.
- Explicitly advice-only: it does not execute tools, grant authorization, expand scope, or claim that an action was performed.

## GUI
- Added a Cybersecurity Advisor panel with an Ask AI button.
- Advice is presented in plain language so non-technical authorized users can ask security questions without needing terminal commands.

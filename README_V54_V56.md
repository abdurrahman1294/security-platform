# V54–V56 — Session & Identity Intelligence

## V54 — Session Intelligence
Builds a session lifecycle model from the existing authentication surface model without collecting or storing credentials, cookies, tokens, or other secret values.

Artifacts:
- `evidence/session-intelligence-v54.json`
- `reports/session-intelligence-v54.md`

## V55 — Bounded Session Observations
Provides a tightly bounded, operator-approved observation layer for session-related surfaces.

Safety boundaries:
- GET only
- scope allowlist required and must be non-empty
- maximum request budget
- redirects are not followed
- response metadata only
- sensitive `Set-Cookie` values are redacted
- no credential/token collection
- no state-changing requests

Artifacts:
- `evidence/session-observations-v55.json`
- `reports/session-observations-v55.md`

## V56 — Identity Transition Decisions
Turns the session model and optional observations into prioritized operator decision support for lifecycle transitions such as logout invalidation, session rotation, timeout, re-authentication, and role transitions.

Artifacts:
- `evidence/identity-transitions-v56.json`
- `reports/identity-transitions-v56.md`

## CLI

```bash
python3 orchestrator.py -c CLIENT -t TARGET --session-intelligence
python3 orchestrator.py -c CLIENT -t TARGET --session-observe --scope-file config/scope.example.txt
python3 orchestrator.py -c CLIENT -t TARGET --identity-transitions
python3 orchestrator.py -c CLIENT -t TARGET --session-engine
```

`--session-engine` builds V54, asks for explicit approval before V55 observations, then builds V56.

## Security principle

The framework models identity and session behavior, but it does not autonomously bypass authentication, steal credentials, replay secrets, alter account state, or authorize exploitation. Consequential testing remains explicitly operator-controlled.

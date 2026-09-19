# V77–V82 — Unified Security Operator

This milestone turns the framework from a collection of versioned engines into an auditable operator layer that can route work across pentest, bug-bounty, and OSINT capabilities.

## Components
- **V77 Security Brain:** evidence-aware capability routing.
- **V78 Evidence Memory:** cross-module artifact index with secret redaction and hashes.
- **V79 Task Router:** prioritized, auditable work queue.
- **V80 Operator Loop:** observe → normalize → prioritize → propose → approve → execute registered safe task → record → re-evaluate.
- **V81 Unified Assessment Controller:** combines the existing V1–V76 stacks by operating mode.
- **V82 Final Intelligence:** single operator-facing artifact summary.

## Modes
- `pentest`: authorized assessment workflows.
- `bugbounty`: scope/policy-first bounty workflows.
- `osint`: passive public-source research planning.
- `auto`: combines the applicable intelligence layers.

## Examples

OSINT (passive planning):
```bash
python3 orchestrator.py -c Research -t example.com --operator --intelligence-mode osint --osint-objective "technology research"
```

Authorized pentest operator mode:
```bash
python3 orchestrator.py -c Client -t example.com --operator --intelligence-mode pentest --scope-file config/scope.example.txt
```

Bug bounty:
```bash
python3 orchestrator.py -c Program -t example.com --operator --intelligence-mode bugbounty --program-name "Example Program" --program-policy policy.json
```

## Safety boundary
The operator layer does not provide unrestricted autonomous exploitation. Credential theft, persistence, lateral movement, exfiltration, destructive actions, and arbitrary shell execution remain outside the autonomous decision layer. Active/consequential testing remains scope- and approval-gated.

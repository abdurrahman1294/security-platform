# V71–V76 — Bug Bounty + OSINT Intelligence Layer

This milestone adds two operator modes to the V1–V70 platform:

- **Bug bounty mode:** program-policy/scope-first planning, finding triage, duplicate/reportability review, and submission-ready report drafts.
- **OSINT mode:** passive public-source research planning, search pivots, source categories, and confidence-aware entity graphing.
- **Auto mode:** prepares both bug-bounty and OSINT intelligence layers together.

## Commands

```bash
python3 orchestrator.py -c PROGRAM -t target.example --bug-bounty --scope-file config/scope.example.txt
python3 orchestrator.py -c RESEARCH -t example.com --osint --osint-objective "attack surface research"
python3 orchestrator.py -c WORK -t example.com --intelligence-mode auto --program-name "Authorized Program"
```

### Safety

Bug-bounty active testing remains governed by the existing authorization and scope gates. OSINT is designed for public, lawful sources and does not collect credentials, access private accounts, perform doxxing, or make unsupported identity/ownership claims. Reports are drafts; the platform never auto-submits a bounty.

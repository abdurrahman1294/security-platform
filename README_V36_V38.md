# V36–V38 Controlled Proof Expansion

## V36 — Controlled Proof Adapter Expansion
Adds narrowly scoped verification adapters:
- `http-sqli-boolean-differential`: bounded boolean differential check for SQL-injection findings; no extraction or state change.
- `lab-ssrf-local-canary`: synthetic-lab-only SSRF canary check; no external canary is contacted.

## V37 — Proof Execution Guard
All new adapter execution uses a central guard enforcing:
- non-empty scope allowlist
- HTTP(S) only
- maximum 3 requests
- maximum 64 KiB response body
- no redirect following
- per-request scope checking
- request metadata ledger

## V38 — Proof Coverage & Validation Analytics
Produces adapter coverage and proof outcome statistics from the guarded execution ledger.

### Safety boundary
This milestone does not add arbitrary payload execution, command execution, persistence, credential theft/access, lateral movement, exfiltration, or unrestricted exploit automation.

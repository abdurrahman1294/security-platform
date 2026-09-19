# V2.2 Controlled Attack & Validation Expansion

## Major expansion
V2.2 broadens the disposable-lab penetration-testing surface with 20 additional controlled vulnerability-class validators, while retaining the existing recon, web, API, authentication, authorization, AD, AWS/cloud, evidence, reporting, OSINT and bounty specialist capabilities.

### New controlled vulnerability classes
1. SSRF
2. Command-injection boundary
3. SSTI
4. XXE
5. File-upload boundary
6. CSRF
7. CORS
8. Host-header injection
9. CRLF/header injection
10. JWT validation weakness
11. GraphQL exposure
12. WebSocket authorization
13. Insecure deserialization
14. LDAP injection
15. NoSQL injection
16. Prototype-pollution risk
17. HTTP request-smuggling parser differential
18. Cache poisoning
19. OAuth flow misconfiguration
20. Race-condition/state-transition weakness

These are deterministic disposable-lab proof fixtures. They are not unrestricted internet exploit modules.

## Reliability corrections
- Centralized strict loopback URL parsing for lab adapters.
- No redirect following for controlled requests.
- Query-bearing request URLs are supported while target-base URLs remain strict.
- Bounded timeout and response size controls are enforced.
- Persistence validation verifies the exact mechanism and disposable-marker state change.
- Lateral validation rejects prefix-confusable loopback addresses and identical endpoints.
- Attack-chain blocked/dry-run exits now always write a final evidence artifact.
- Evidence reasoning consumes both legacy and V2.2 controlled-validation evidence.
- Added in-memory ROE construction and a safe single-use approval-token convenience method.
- Added a 20-pass pre-active-test regression gate.

## Verification
- Full pytest suite: PASS
- 20-pass pre-active-test gate: PASS 20/20
- Full application import audit: PASS 212/212
- compileall: PASS
- CLI engine discovery: PASS
- Controlled catalog mock integration: PASS 20/20
- Legacy controlled validation mock integration: PASS 7/7
- No external/production target execution performed.

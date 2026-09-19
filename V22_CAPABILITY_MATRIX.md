# V2.2 Controlled Penetration-Testing Capability Matrix

The engine now has a broad lab validation catalog covering 20 additional vulnerability classes: SSRF, command injection, SSTI, XXE, file upload, CSRF, CORS, host-header injection, CRLF/header injection, JWT validation weakness, GraphQL exposure, WebSocket authorization, insecure deserialization, LDAP injection, NoSQL injection, prototype-pollution risk, HTTP request-smuggling parser differentials, cache poisoning, OAuth flow misconfiguration, and race-condition/state-transition weaknesses.

These are implemented as bounded disposable-lab proof adapters. They do not provide unrestricted exploit payloads, arbitrary command execution, C2, stealth, credential spraying, uncontrolled propagation, or real-data exfiltration.

## Validation quality
- Strict loopback URL parsing
- No redirect following
- Bounded request time and response size
- Fixed lab markers rather than caller-controlled code execution
- Per-capability evidence records
- Evidence reasoner consumes both V2.1 and V2.2 evidence
- Attack-chain output preserves a final evidence artifact even on blocked/dry-run exits

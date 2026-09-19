# V3.37–V3.41 Assurance Expansion

## V3.37 Unified Specialist Adapter Fabric
- Introduces a canonical specialist lifecycle: preflight → approval → execution → evidence → failure → finding → validation → remediation → retest.
- Normalizes specialist capabilities into governed adapter records.
- Adds enterprise adversary-emulation planning metadata without autonomous endpoint agents, credential theft, persistence, covert C2, unrestricted execution, or scope expansion.

## V3.38 Web/API Assurance Corpus
- Adds a 20-class web/API assurance catalog covering transport, headers, cookies, CORS, caching, methods, redirects, validation, encoding, authentication/authorization boundaries, rate-limit observation, GraphQL, API drift, WebSockets and upload controls.
- Keeps execution bounded and specialist/operator controlled.

## V3.39 Fuzz Campaign Fabric
- Adds bounded campaign planning, deterministic campaign IDs, corpus lifecycle metadata, deduplication/minimization, crash fingerprinting and reproduction references.
- Fuzz execution remains delegated to approved specialist/testbed adapters.

## V3.40 Engagement Datastore
- Adds a durable local engagement index and analytics metadata for evidence freshness, finding trends, tool reliability, coverage deltas and retest regressions.
- Keeps artifacts local and secret-redacted.

## V3.41 Identity Assurance
- Adds a protocol matrix for Kerberos, LDAP/LDAPS, NTLM, SMB, WinRM, RDP, SSH, OAuth/OIDC, SAML, MFA and DNS identity controls.
- Uses operator-supplied identities only and explicitly excludes secret collection and credential spraying.

## Cross-version hardening
- V3.33 claim status now reports the achieved assurance level instead of labeling any request that is merely met as “validated”.
- V3.35 self-security audit now honors `include_tests=False` so production-only audits can exclude test/tool directories.

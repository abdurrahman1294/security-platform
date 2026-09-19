# V3.30 Engineering Audit

## Scope
This audit reviewed the current repository after the V3.30 integration work. It covered the new canonical execution fabric, its CLI/platform integration, the existing approval control path, source-level execution boundaries, documentation/version consistency, compilation, and the complete automated regression suite.

## Findings and disposition

| ID | Finding | Severity | Disposition |
|---|---|---|---|
| V330-01 | CLI failed when invoked from repository root as `python security_platform/cli/securityctl.py` because the repository root was not on `sys.path`. | Medium | Fixed with a small bootstrap path insertion; both root-path and normal invocation now work. |
| V330-02 | V3.30 secret filtering only matched exact field names in the first implementation. Keys such as `auth_token` could escape field filtering. | High | Fixed with normalized secret-key matching and substring detection before artifact persistence. |
| V330-03 | Architecture release verification still described the V3.29 suite as the current suite and did not distinguish V3.29 planning from V3.30 execution integration. | Low | Documentation corrected. |
| V330-04 | The V3.30 planner could be described as an execution engine if its delegation boundary was not explicit. | Medium | API and artifact now state `delegation-only` and `capability_synthesis=false`; no new execution adapter is created by V3.30. |
| V330-05 | Approval tokens in the existing V3.22 R4 path previously lacked enforced single-use consumption. | High | Already corrected in the current tree using request-bound `consume_token()`; regression coverage retained. |
| V330-06 | Several legacy specialist modules write JSON directly instead of the newer atomic evidence writer. | Medium | Not silently refactored because these modules are historical/independent surfaces. This remains a hardening backlog item. |
| V330-07 | Some specialist modules invoke subprocesses directly rather than through ToolManager. | Medium | They use `shell=False` and bounded argument construction in the inspected cases, but this is a transitional architecture inconsistency. New generic execution must use ToolManager. |
| V330-08 | `ruff` is not installed in the current environment. | Informational | Full pytest and AST compilation were used instead; linting should be run in CI with the pinned development environment. |

## Invariants verified

- Scope is never expanded by the V3.30 planner.
- Authorization is never inferred from reachability or findings.
- Execution cannot be requested as a substitute for authorization.
- Current authorization is checked separately from historical authorization.
- Hypotheses remain hypotheses; they are not compromise claims.
- Denied execution classes are not selected by the integration layer.
- Secret-bearing fields are removed before V3.30 artifact persistence.
- Evidence quality is preserved as metadata rather than converted into certainty.
- Failures are represented as first-class state and feed bounded retry/replan decisions.
- Completed steps can be represented in canonical state for resume-aware planning.
- Remediation produces a separate retest plan requiring fresh evidence.
- Invalid perspectives block the campaign rather than being silently normalized.
- Target identity is locked into canonical state and mismatches block the campaign.

## Source-level review

### Execution boundary
The inspected ToolManager uses `shell=False`, allowlisted tool identities, hardened argv validation, sanitized environment handling, bounded timeouts and a durable execution ledger. The V3.30 layer does not bypass that boundary.

### Approval boundary
The current R4 path requires authorization, exact ROE permission, a request-bound approval identifier/token, authoritative scope, and loopback-only built-in execution. Token consumption is durable and single-use.

### Failure behavior
The new V3.30 fabric distinguishes transient/tool/network failures from permanent or governance-related failures and emits retry/replan guidance without changing scope or authorization state.

## Test campaign

### Automated
- Full pytest suite: **PASS**
- Python AST parse of all modules/security-platform Python sources: **0 syntax errors**
- Python bytecode compilation: **PASS**
- V3.30 focused suite: **PASS**
- V3.29 focused suite: **PASS**
- CLI V3.30 suite: **PASS**
- CLI V3.30 plan generation: **PASS**

### Adversarial scenarios
V3.30 defines **36** control-plane scenarios covering canonical-state consistency, scope/authorization revocation, stale and contradictory evidence, duplicate/malformed inputs, timestamp ordering, perspective divergence, resume/interruption, failure replan, capability unavailability, denied-class exclusion, secret redaction, remediation/retest, state drift, lineage, teardown status and evidence-only reporting.

## Remaining engineering risks

1. The repository contains a large historical module surface; not every legacy writer has been migrated to atomic persistence.
2. A subset of specialist adapters still execute directly with `subprocess.run(..., shell=False)`. Their safety is more fragmented than the ToolManager path.
3. V3.30 is a canonical integration/control plane, not proof that every specialist domain has complete real-world coverage.
4. A vulnerability verdict still requires domain-specific evidence and human review for novel/business-logic cases.
5. Tool availability, OS permissions, network perspective and target behavior can prevent a technically valid validation plan from being executed.

## Final audit decision

**PASS WITH HARDENING BACKLOG.**

No release-blocking defect was found after the fixes above. The remaining issues are architectural consistency and migration debt rather than an authorization bypass or uncontrolled execution path.

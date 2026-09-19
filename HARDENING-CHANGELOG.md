# Hardening Changelog

Scope: the modules with real logic (not the metadata-stub cluster, which was
left untouched per your instruction — you're deleting those separately).

## Critical fix: findings.json format mismatch (systemic)

`orchestrator.py`'s vuln_scan phase writes nuclei output with `-json-export`,
which produces a **JSON array**. Several modules assumed **JSONL** (one
object per line) when reading it back, and silently parsed to an *empty*
findings list against real scan output — no error, no warning, just zero
findings downstream of a fully successful scan.

Added `modules/findings_io.py` — one shared, format-tolerant loader
(`load_findings_file`) used everywhere findings are read, so the format only
has to be handled correctly in one place.

Fixed to use it (or an equivalent robust loader):
- `modules/attack_graph.py`
- `modules/controlled_validation.py`
- `modules/adaptive_engine_v41.py`
- `modules/asset_inventory.py`
- `modules/correlation_engine.py`
- `modules/data_normalization_v24.py`
- `modules/exploiter.py`
- `modules/report_pack.py`
- `modules/smart_report.py` (this is your client-facing executive summary —
  it would have said "0 automated findings" on a report full of criticals)
- `modules/technology_intelligence.py`
- `modules/web_surface_v45.py`
- `modules/final_report_v69.py`

Verified by actually running each against a synthetic engagement directory
with array-format findings, not just by reading the code.

Confirmed clean (read `findings.json` only for hashing/existence/mtime, or
only read already-normalized artifacts, which now inherit the fix
transitively): `bounty_triage_v72.py`, `change_detection_v108.py`,
`closure_engine_v29.py`, `controlled_exploitation_v30.py`,
`correlation_v107.py`, `evidence_helper.py`, `exploit_planner_v35.py`,
`finding_dedup_v25.py`, `production_layer_v211_v225.py`,
`remediation_intelligence_v26.py`, `residual_risk_v32.py`, `timeline.py`.

## Other fixes

- `modules/controlled_validation.py`: `_in_scope()` no longer swallows every
  exception into `return False`. A real bug in the scope loader (bad file,
  bad import) now raises instead of looking identical to "target not in
  scope" — those need very different responses from an operator.
- `modules/attack_graph.py`: the pairwise capability-correlation and
  same-parent-domain passes are O(n²) over findings. Capped at the top 1,500
  findings by severity so a large real scope (thousands of nuclei hits)
  can't turn this into a multi-million-comparison stall. Every finding still
  becomes a graph node regardless; only the expensive pairwise correlation
  is capped, and the graph's `notes` field says so when it happens.

## Deliberately not touched

- `orchestrator.py`, `modules/scope.py`, `modules/validators.py`,
  `modules/security.py` from the earlier round (already hardened: real
  scope enforcement, no `shell=True`, input validation, tracked phase
  results).
- `modules/ad_advanced.py` — reviewed, no code issues; it's a static
  methodology/reference document generator (standard, publicly documented
  AD pentest technique names — Kerberoasting, AS-REP roasting, BloodHound,
  ACL abuse — at the same level as any AD security training material), not
  something that needed hardening.
- The location/device-recovery/OSINT-entity-graph/geofencing cluster (v176,
  v187, v191–v210 in `modules/`) — left as the non-functional metadata stubs
  they already were. Per our conversation: this combination of capabilities
  can't be given real ownership verification beyond what the vendor's own
  authenticated recovery flow already provides, and building it out would
  produce something indistinguishable from stalkerware regardless of intent.
  You said you're deleting these; recommend doing that before this goes
  anywhere near a real engagement.

## 2026-09-03 — Findings I/O reliability correction
- Added/standardized `modules/findings_io.py` as the single format-tolerant findings loader.
- Supports Nuclei JSON arrays, JSONL, findings-wrapper objects, and single-finding JSON objects.
- Repointed controlled proof lookup and bug-bounty triage/prioritization to the shared loader where raw findings are consumed.
- Added regression tests covering all supported findings representations.
- Confirmed the full regression suite remains green.

## 2026-09-03 — Scope-escape via unfollowed-redirect assumption (critical)

Independent code review found that the "no redirect following" invariant
claimed for bounded/scope-checked probing was **not actually enforced**.
`modules/controlled_validation.py`, `modules/web_probe_v49.py`, and
`modules/controlled_exploitation_v30.py` scope-checked a URL and then
issued the HTTP request with the *default* urllib opener, which
transparently follows 3xx redirects. Reproduced empirically with two local
HTTP servers: a scope-checked host returning a 302 to a second,
deliberately out-of-scope host caused each of the three modules to make a
live request to the unauthorized host, while still recording
`"scope_checked": true` / `"result": "observed"` against the original,
pre-redirect URL. The open-redirect proof adapter additionally hardcoded
`"follow_redirects": False` into its output even though nothing enforced
that.

- Added `modules/safe_http.py` — a single request helper built on a
  `NoRedirect` opener (matching the pattern already used correctly in
  `modules/session_observation_v55.py`). A 3xx response is returned as-is,
  with the `Location` header surfaced to the caller; it is never fetched.
- Repointed `controlled_validation._http_head`, `web_probe_v49.run`, and
  `controlled_exploitation_v30._request` (and therefore the exploit
  adapters in `exploit_adapters_v33.py`, which import it) to the shared
  helper.
- `controlled_validation.validate()` now reports
  `"reachable-observed-redirect-not-followed"` instead of
  `"reachable-observed"` when the response was a redirect, so the ledger
  and report no longer conflate "the original URL answered" with "the
  original URL answered with a 200".
- Also consolidated `modules/attack_graph.py`'s and
  `modules/exploit_planner_v35.py`'s remaining duplicate finding-parsing
  logic onto `modules/findings_io.load_findings_file` (they previously had
  their own array/JSONL-tolerant copies that, unlike the shared loader,
  did not support the `{"findings": [...]}` wrapper format).
- Added `tests/test_redirect_scope_and_loader_fixes.py`: spins up real
  loopback HTTP servers to prove the out-of-scope host receives zero
  requests through any of the three affected modules, plus loader-parity
  tests for the wrapper format.
- Full suite: 96/96 passing (90 pre-existing + 6 new).


## 2026-09-03 — V226-V231 Deep Operational Excellence
- Added evidence-driven exploitation intelligence and safe-proof eligibility.
- Added finding-aware validation planning/execution handoff to V37 guards.
- Added read-only AD assessment with explicit approval and environment-based credentials.
- Added account-bound read-only AWS inventory with explicit account allowlist.
- Added Web/API coverage and blind-spot accounting.
- Added V231 deep quality gate.
- Hardened V100 integrated toolchain so missing scope no longer falls back to unrestricted discovered assets.
- Refined legacy exploitation/AD guidance modules to avoid embedding credentials or unrestricted offensive commands.

## 2026-09-03 — V232 deep pre-test audit and correction pass

- Audited all 185 Python modules before reality testing.
- Added per-tool argument allowlists, output/input path confinement, executable identity verification and minimized child environments.
- Routed legacy API/auth/server/internal/screenshot execution through the registered tool boundary.
- Added global authorization gating to V228/V229 active execution paths.
- Hardened AD credentials with temporary 0600 credential files and the registered NetExec adapter.
- Hardened AWS execution with exact STS caller-account verification against `AWS_ALLOWED_ACCOUNT_IDS`.
- Replaced most broad JSON/error swallowing with typed exceptions and atomic JSON loading.
- Upgraded several V171-V210 modules from static policy emitters to evidence-driven evaluators.
- Removed stale `add_excellence.py` and unused `evidence_helper.py`.
- Added dependency manifests, canonical architecture/module-status documentation and repeatable `tools/audit_engine.py`.
- Added behavioral and import-surface regression tests.
- Final verification: 105 tests passed, 185/185 modules imported, 0 syntax failures.

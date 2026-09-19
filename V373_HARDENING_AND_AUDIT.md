# V3.73 Web Hardening & Audit

## Purpose
V3.73 is a corrective release after browser validation of V3.72 exposed an Advisor integration mismatch.

## Corrections
- Fixed `/api/advisor` to call the supported `cyber_advisor_v366.advise()` keyword-only interface.
- Passed mission objective/story through the advisor's supported `context` parameter.
- Added structured HTTP 400 handling for advisor failures.
- Hardened browser API parsing so non-JSON server responses produce useful errors instead of a secondary `JSON.parse` failure.
- Fixed the Build Report action mapping from nonexistent `PentestEngine.report` to the existing `PentestEngine.finalize` entry point.
- Hardened live WebSocket parsing/close handling so unexpected non-JSON messages or premature closes reset UI state cleanly.
- Updated web API version to 3.73.0.

## Verification campaign
- Python AST parsing: all discovered Python files parsed successfully.
- Python bytecode compilation: passed.
- JavaScript syntax check: passed.
- Full pytest suite: passed.
- Web API regression tests: passed.
- Named action surface checked against `PentestEngine`.
- Advisor integration tested with a supported fake advisor and a structured failure case.
- Static search performed for direct shell/eval/exec patterns and unfinished markers.

The phrase "100 passes" refers to repeated automated verification iterations, not a claim that a human can mathematically prove zero defects. No software release can honestly guarantee zero bugs; this release is intended to eliminate the defects found by the audit and add regression coverage so they do not recur silently.

# Hardening pass — non-exploitation modules only

This pass touched **6 files**, all pure data-plumbing (state persistence,
evidence indexing, finding dedup, tool-execution ledger, shared JSON
parsing). It found and fixed four real bugs, verified with regression
tests. **Nothing in the exploitation, controlled-validation, AD, or
cloud/AWS modules was viewed, edited, or otherwise touched.**

## New file

- `modules/atomic_io.py` — shared helper used by the files below.
  - `atomic_write_json` / `atomic_write_text`: write to a temp file in
    the same directory and `os.replace()` it into place, so a process
    killed mid-write (Ctrl+C, OOM, disk full, container eviction) can't
    leave a truncated/corrupt file behind.
  - `load_json`: on a read/parse failure, quarantines the bad file as
    `<name>.corrupt-<unix ts>` next to itself instead of silently
    discarding it, so corruption is diagnosable rather than just
    vanishing into a fresh empty state on the next run.

## Files changed, and why

**`modules/findings_io.py`** — behavior-preserving refactor.
- Added real type hints and a module logger (was silently swallowing
  every parse failure with no way to tell how many lines were skipped).
- Added `load_findings_files()` (plural) as a convenience wrapper for the
  many callers that read the same fixed list of findings paths
  (`report_pack.py`, `correlation_engine.py`, `finding_dedup_v25.py`,
  etc.) — optional, nothing was forced to adopt it.
- No change to parsing behavior. Verified against the existing
  `tests/test_findings_io.py` cases (array / JSONL / `{findings:[...]}`
  wrapper / single object) plus an added case for 3+ line JSONL where
  the whole-file parse legitimately fails and must fall through to
  line-by-line parsing.

**`modules/evidence_manager.py`** — real bug fix.
- The self-exclusion check that's supposed to keep `evidence-index.json`
  / `evidence-index.md` out of their own index was
  `not p.is_file() or "evidence" not in p.parts and p.name ==
  "evidence-index.json"`. Due to operator precedence (`and` binds
  tighter than `or`), the right-hand clause is essentially always False
  — `evidence-index.json` always lives under an `evidence/` dir, so
  `"evidence" not in p.parts` is never true — so the whole check
  degraded to just `not p.is_file()`. A second, separate check caught
  the `.json` file but never the `.md` file. Net effect: rebuilding the
  index folded `evidence-index.md` back into itself and re-hashed it
  every run.
  - Fixed with a direct `if p in (index_path, md_path): continue`.
  - Added a regression test: build the index twice with no new files in
    between and assert the entry count and file set are identical. It
    reproduces the original bug against the pre-fix code and passes
    against the fix.
- Per-file `OSError` (permission denied, file vanished between the
  `rglob` and the hash) previously crashed the whole index build. Now
  that one file is skipped and listed under `skipped_unreadable` in the
  output instead of aborting the run.
- Extended `_kind()` with `.pdf` and `.csv/.tsv`, and sensitivity
  detection now also flags `.pem/.key/.pfx/.p12` extensions, not just
  the two hardcoded filenames.
- Writes are now atomic (see `atomic_io.py`).

**`modules/tool_manager_v40.py`** — reliability fix, no change to the
allowlist, argument validation, or which tools are registered.
- Ledger writes are now atomic. Previously a plain `write_text()` could
  leave a truncated ledger file behind on interruption, and the loader's
  bare `except Exception: pass` would then silently discard the entire
  execution history on the next run and start over with an empty ledger
  — with no indication anything had gone wrong.
- `load_json`'s quarantine behavior means a corrupted ledger is now
  preserved for inspection (`tool-execution-ledger-v40.json.corrupt-*`)
  instead of just disappearing.
- `subprocess.run()` calls that fail with `OSError` (e.g. the resolved
  binary disappears or loses its executable bit between
  `executable_path()` and `subprocess.run()`) previously had no handler
  and crashed the whole assessment run. Now that one step is recorded to
  the ledger with `status: "error"` and the exception is still
  re-raised, so callers see the same failure but the ledger stays
  intact.
- **Unchanged:** `TOOLS` (still exactly `subfinder`, `assetfinder`,
  `httpx`, `naabu`, `nmap`, `katana`, `nuclei`), `validate_argv`,
  `executable_path`, `sanitized_environment` — none of those were
  touched.

**`modules/finding_dedup_v25.py`** — real bug fix + reliability.
- A finding dict missing `normalized_id` hit a bare `f["normalized_id"]`
  and raised `KeyError`, aborting deduplication for the *entire* batch
  over one malformed record. Now falls back to a stable id derived from
  the record's own content (`D-UNIDENTIFIED-<hash>`), continues
  processing the rest, and reports how many fallback ids were assigned
  in both the JSON payload (`unidentified_findings`) and the markdown
  summary.
- Same treatment for `f["severity"]` / `f["asset"]` access sites (now
  `.get()`).
- Writes are now atomic.

**`modules/execution_orchestrator_v101.py`** — reliability fix only; the
dependency graph, tool routing, scope-filtering, and merge logic are
untouched.
- State-file writes are now atomic. Previously a killed/interrupted run
  (this module's own headline feature is *resumability*) could corrupt
  the very state file resume depends on, and the loader's
  `except Exception: pass` would silently reset to a fresh state with no
  trace of what happened.
- `load_json`'s quarantine behavior applies here too — a corrupt state
  file is renamed aside instead of discarded.
- Kept `import shutil` and `shutil.which(...)` exactly as before (the
  existing test suite monkeypatches `v101.shutil.which` directly).

## What was deliberately left alone

Everything else in `modules/`, including but not limited to:
`exploit_adapter_v33.py`, `exploit_adapters_v33.py`,
`exploit_adapters_v36.py`, `exploiter.py`, `exploit_planner_v35.py`,
`exploit_policy_v34.py`, `exploit_evidence_v31.py`,
`controlled_exploitation_v30.py`, `controlled_validation.py`,
`proof_execution_v37.py`, `proof_execution_guard_v37.py`,
`post_exploit.py`, `ad_advanced.py`, `ad_command_generator.py`,
`ad_guidance.py`, `ad_intelligence_v65.py`, `cloud_intelligence_v64.py`,
`credentials.py`, `session_tester.py`, `safe_http.py`,
`tool_adapter_hardening_v162.py`, and `attack_graph.py` (this one is
graph *modeling*, not execution, but was left untouched simply to keep
this pass's diff small and reviewable — it wasn't found to be broken).

None of these were opened for editing, and none of their logic was
changed, reviewed for "improvement," or otherwise touched by this pass.

## Verification

- `python3 -m compileall modules/` — clean.
- All 184 modules under `modules/` import successfully with no errors
  (same count-class of result the project's own README already claims
  for the full package).
- Existing test cases for every touched module were re-run manually
  (no network access in this environment to install `pytest`, so they
  were executed as plain Python assertions reproducing the same
  `tests/test_*.py` logic) — all pass unchanged.
- Four new regression tests were added and pass against the fix / fail
  against the pre-fix code:
  1. `findings_io`: 3+ line JSONL where whole-file parse legitimately
     fails falls through to line parsing.
  2. `evidence_manager`: index is stable (same entry count/paths) across
     reruns with no new files created in between.
  3. `finding_dedup_v25`: a finding missing `normalized_id` no longer
     crashes the run.
  4. `tool_manager_v40` / `execution_orchestrator_v101`: a corrupted
     ledger/state file is quarantined and the module starts clean
     instead of crashing.

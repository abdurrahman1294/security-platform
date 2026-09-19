# V39–V41 Pentest Mission Engine

## V39 — Assessment Orchestrator
Introduces a durable mission plan and task state machine. It represents the engagement as dependent phases: authorization, recon, enumeration, web, vulnerability discovery, API/server assessment, intelligence, controlled proof review, and reporting.

## V40 — Tool Manager
Adds an allowlisted tool registry and command execution ledger for approved assessment utilities. Commands are executed with `shell=False`, explicit argv, per-tool timeouts, and durable execution metadata.

## V41 — Adaptive Assessment Decisions
Reads engagement artifacts and produces ranked next-action decisions based on current assets, findings, validation candidates, attack graph state, and proof history. It does not select arbitrary exploits and preserves human approval for consequential actions.

## Mission command
`python3 orchestrator.py -c CLIENT -t TARGET --mission --full --scope-file config/scope.example.txt`

The mission command remains behind the existing authorization and scope gates. Controlled proof/exploitation is not silently executed; it remains separately approval-gated.

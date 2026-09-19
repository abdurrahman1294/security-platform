# V3.13 — Governed Mission Fabric

V3.13 turns the V3.12 adaptive mission into an execution contract with a hard approval boundary.

## What changed

- Added a workflow-coverage matrix for major Metasploit/Cobalt Strike-style workflow categories.
- Added governed execution planning that maps adaptive specialist roles to registered platform actions.
- Added durable approval requests tied to the exact action and target.
- Added single-use approval-token consumption before active execution.
- Re-checks authorization and authoritative scope immediately before execution.
- Continues to use the existing `ToolManager`/`HardenedToolExecutor`; this layer does not create an alternate command-execution path.
- Produces durable JSON artifacts for the plan, approval requests, coverage, and execution result.
- Explicitly distinguishes capabilities that are implemented/composed from capabilities that remain external-specialist or lab-only.

## Execution lifecycle

```text
adaptive evidence
      ↓
next-best specialist/action
      ↓
bounded mission plan
      ↓
operator approval request
      ↓
operator approval → single-use token
      ↓
authorization re-check + scope re-check
      ↓
registered ToolManager action
      ↓
execution/evidence ledger
      ↓
new evidence
      ↓
re-plan
```

No approval token means **no active action**.

## CLI

Build coverage:

```bash
python security_platform/cli/securityctl.py fabric --client CLIENT --target TARGET --output-dir OUTPUT --scope SCOPE --action coverage
```

Build a bounded governed mission:

```bash
python security_platform/cli/securityctl.py fabric --client CLIENT --target TARGET --output-dir OUTPUT --scope SCOPE --action mission-plan --objective general --max-steps 8
```

Create approval requests:

```bash
python security_platform/cli/securityctl.py fabric --client CLIENT --target TARGET --output-dir OUTPUT --scope SCOPE --action request-approvals --objective general --max-steps 8
```

Approve requests through the existing durable approval queue, then execute with the resulting request-bound token(s):

```bash
python security_platform/cli/securityctl.py fabric --client CLIENT --target TARGET --output-dir OUTPUT --scope SCOPE --action execute --authorize --approval-token REQUEST_ID=TOKEN
```

Multiple approved actions can be supplied by repeating `--approval-token`.

## Coverage interpretation

The matrix deliberately does **not** claim that this platform internally reproduces every implementation primitive of specialist red-team products. Metasploit has exploit, auxiliary, payload and post modules plus RPC/session workflows; Cobalt Strike includes Beacon, C2, extensibility, collaboration and reporting. The platform instead composes its own governed assessment capabilities and can interoperate with specialist ecosystems through adapters/evidence contracts.

The current safe fabric therefore treats payload generation/C2, stealth/evasion, credential capture/theft, persistence deployment, and destructive operations as separate governed/external or lab-only capabilities rather than silently implementing them.

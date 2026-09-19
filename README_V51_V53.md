# V51–V53 — Authentication & Authorization Intelligence

This milestone adds an authentication/authorization intelligence layer on top of the V45–V50 web/API model.

## V51 — Authentication Intelligence

Builds a structured model of candidate authentication surfaces and trust boundaries from the existing endpoint inventory.

It identifies login, logout, token, session, federation and account-management candidates without collecting or storing passwords, cookies, bearer tokens or JWTs.

Artifact:
- `evidence/auth-intelligence-v51.json`
- `reports/auth-intelligence-v51.md`

## V52 — Authorization Test Matrix

Creates an operator-reviewed comparison matrix for generic role boundaries:

- anonymous → authenticated
- authenticated → resource-owner
- authenticated → privileged
- resource-owner → authenticated
- privileged → authenticated

The matrix covers authentication boundaries, horizontal/vertical access control and least-privilege review. It is planning-only and non-destructive.

Artifact:
- `evidence/authorization-matrix-v52.json`
- `reports/authorization-matrix-v52.md`

## V53 — AuthZ Decision Engine

Combines V51/V52 and available bounded observations to rank the next manual assessment action.

Examples:
- map authentication flow
- confirm authorized role pairs
- manually validate horizontal access control
- manually validate vertical access control
- review least privilege

It never grants authorization, bypasses access controls, uses credentials, mutates application state, or executes exploitation.

Artifact:
- `evidence/authz-decisions-v53.json`
- `reports/authz-decisions-v53.md`

## CLI

```bash
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --auth-engine
```

Individual operations:

```bash
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --auth-intelligence
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --authorization-matrix
python3 orchestrator.py -c CLIENT -t TARGET --output-dir OUTPUT --authz-decisions
```

## Lifecycle

```text
V45–V47 Deep Web/API Model
        ↓
V48 Test Matrix
        ↓
V49 Bounded Observation
        ↓
V50 Adaptive Decisions
        ↓
V51 Authentication Intelligence
        ↓
V52 Authorization Matrix
        ↓
V53 AuthZ Decisions
        ↓
Controlled Validation / Proof
```

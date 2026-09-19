# Security Platform v2.0 — Controlled Lab Attack Chain

v2.0 adds a **lab-only, evidence-driven attack-chain demonstration**. It does
not turn the platform into an unrestricted exploitation engine.

## Chain

```text
Initial Access Context
       ↓
Credential Discovery
       ↓
Credential Verification
       ↓
Privilege Proof
       ↓
Persistence Proof
       ↓
Lateral Authentication → Second Disposable Host
       ↓
Fake Objective
```

Every transition requires concrete evidence from the previous stage. The
engine never marks a stage successful just because a request was attempted.

## Safety boundary

- Loopback-only lab targets.
- Explicit authorization required.
- `controlled_attack_chain_test` is R4 and requires an approved token plus ROE.
- Persistence is a benign marker fixture inside a disposable container.
- Lateral movement is network authentication to a second lab service; it does
  not execute arbitrary remote commands.
- Fake objective data only.
- R5 actions remain permanently denied.
- No credential spraying, stealth persistence, destructive payloads, real data
  exfiltration, uncontrolled propagation, or unrestricted RCE.

## Run

Start the lab from `lab/security-platform-lab`:

```bash
docker compose up -d --build
```

Use a lab ROE that explicitly permits only `controlled_attack_chain_test` and
keeps `production_change_allowed=false`, `third_party_assets_allowed=false`,
and `fake_data_only=true`.

First create an approval request through the existing autonomy workflow:

```bash
python securityctl.py autonomy -c LAB -t http://127.0.0.1:8080 -o ./output \
  --scope ./config/scope.example.txt --authorize --roe ./lab/security-platform-lab/config_roe.attack-chain.json \
  --request-action controlled_attack_chain_test --request-reason "Run disposable local attack-chain regression test"
```

Approve the returned request ID:

```bash
python securityctl.py autonomy -c LAB -t http://127.0.0.1:8080 -o ./output \
  --scope ./config/scope.example.txt --approve REQUEST_ID
```

Then execute:

```bash
python securityctl.py attack-chain -c LAB -t http://127.0.0.1:8080 -o ./output \
  --scope ./config/scope.example.txt --authorize --execute \
  --roe ./lab/security-platform-lab/config_roe.attack-chain.json \
  --approval-token APPROVAL_TOKEN
```

Evidence is written under `./output/evidence/`, including
`attack-chain-state.json` and `attack-chain-final.json`.

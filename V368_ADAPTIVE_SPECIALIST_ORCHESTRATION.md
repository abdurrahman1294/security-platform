# V3.68 — Adaptive Specialist Orchestration

V3.68 adds an adaptive routing layer above the existing Python/AI engines.

## What it does

- Reads the pentester's objective, story, findings and observations.
- Scores specialist domains such as web, network, cloud, identity, OSINT, attack-path and rare-case reasoning.
- Selects the smallest useful specialist set instead of running every capability blindly.
- Uses only registered `PentestEngine` entry points.
- Reassesses the remaining specialist set after each round and suppresses completed steps.
- Produces `evidence/adaptive-specialist-orchestration-v368.json`.

## Important boundary

The orchestrator does not convert natural-language text into shell commands, grant authorization, expand scope, or bypass specialist controls. Sensitive specialist phases such as cloud, authenticated and AD work require the existing approval token in addition to authorization.

## Example

A story mentioning an unusual JWT/API authorization issue can route primarily to **web + identity + attack-path**, rather than wasting the engagement on unrelated specialists.

A sparse story can still select broad web/network coverage, while a rare/unusual narrative adds the rare-case specialist as a reasoning track.

## Engine API

`PentestEngine.adaptive_specialist_orchestration_v368(...)`

Arguments include `objective`, `story`, `max_specialists`, `max_rounds`, `approval_token`, and `authorized`.

# V3.21 — Functional Universal Assessment Runner

V3.21 turns the V3.20 universal attack-surface fabric from a planning layer into a **bounded functional runner** for the platform's already-registered R0–R2 adapters.

## What changed

- Executes only registered `ToolManager` tools.
- No shell, arbitrary executable, credential capture, persistence, destructive action, propagation, covert C2, or carrier-bypass path is introduced.
- Requires both `--authorize` and `--execute` plus a valid, non-empty scope containing the target.
- Keeps the selected perspective explicit: `internet_ipv4`, `internet_ipv6`, `cellular_ipv4`, `cellular_ipv6`, LAN, VPN, cloud, authenticated, testbed, or physical-lab perspectives.
- Records DNS/IPv4/IPv6 reachability evidence before active execution.
- Produces complete accounting for every selected surface: `executed`, `failed`, `blocked`, `specialist-required`, or `skipped`.
- Limits execution to a bounded step count and per-tool timeout.
- Surfaces without a generic safe adapter are not falsely reported as tested; they are handed off as `specialist-required` for the appropriate domain/lab/artifact workflow.

## Generic functional adapters

The runner currently provides fixed R0/R1 discovery paths for:

- external web / API → `httpx`
- DNS/certificate → `subfinder`
- internet services → `nmap`
- remote access → bounded `nmap` service set
- network devices → bounded `nmap` management-service set
- cellular telecom → bounded `nmap` + `httpx`

Cloud, Kubernetes, identity, mobile, wireless, firmware, OT/ICS, automotive, hardware, reverse engineering, fuzzing, and other specialist surfaces remain represented in the universal fabric and are routed to their dedicated specialist workflows rather than being reduced to generic probes.

## Perspective rule

A cellular perspective means the platform is executed from a cellular-connected vantage (for example, a laptop using mobile tethering). It does **not** imply bypassing CGNAT, IPv6 filtering, carrier controls, authentication, or firewalls. If a target is not reachable from that vantage, the engine records the limitation instead of attempting to defeat it.

## Example

```text
python -m security_platform fabric \
  --client demo \
  --target 203.0.113.10 \
  --scope config/scope.example.txt \
  --output-dir output/demo \
  --action universal-assess \
  --perspective cellular_ipv6 \
  --authorize \
  --execute \
  --input external_web,api,internet_services,remote_access \
  --max-steps 8
```

The resulting evidence is written under the engagement output directory, including `evidence/universal-assessment-v321.json` and the tool-specific artifacts produced through the ToolManager.

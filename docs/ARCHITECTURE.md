# Pentest Automation Framework — Current Architecture

## Purpose

A scope-controlled, evidence-driven platform for authorized security assessments.
It orchestrates approved discovery tools, normalizes their output, correlates
observations, plans validation, records evidence and produces assessment artifacts.
It is not an unrestricted autonomous exploitation agent; planning, evidence reasoning and execution are separate control layers.

## Control boundary

```text
CLI
  -> authorization gate
  -> target/scope validation
  -> registered tool manager
       -> executable identity verification
       -> per-tool flag allowlist
       -> output/input path confinement
       -> minimized child environment
       -> execution ledger
  -> result collection / normalization
  -> intelligence / correlation
  -> operator-approved validation
       -> V33 adapter registry
       -> V34 proof policy
       -> V37 execution guard
  -> evidence / risk / reporting / retest / closure
```

## External tool boundary

The preferred generic external execution path is `ToolManager`. It is the authoritative
path for registered generic assessment tools. A small number of specialist/legacy
adapters still use fixed, non-shell subprocess calls for platform-specific inspection;
these are transitional and must not become arbitrary command interfaces. Nuclei,
NetExec and cloud commands with different safety properties use fixed adapters
rather than a generic arbitrary-command interface.

### Registered security tools

- ProjectDiscovery subfinder
- assetfinder
- ProjectDiscovery httpx
- naabu
- Nmap
- Katana
- Nuclei
- NetExec (read-only AD/SMB subset)

The manager verifies executable identity. A binary with the expected filename
but the wrong program is rejected. This matters because generic programs can
share names with security tools.

## Findings lifecycle

```text
raw tool result
  -> shared loader
  -> normalized finding
  -> confidence / correlation
  -> hypothesis
  -> validation plan
  -> explicit operator approval
  -> bounded proof
  -> evidence
  -> report
  -> remediation
  -> retest
  -> closure
```

Scanner output alone is never treated as confirmed compromise.

## AD

V228 supports a narrow read-only NetExec subset: SMB baseline, users, groups,
password policy and shares. Credentials are supplied through temporary files
under the engagement directory and removed after execution. No spraying,
credential dumping, privilege modification, persistence or lateral movement is
automated.

## AWS

V229 performs only a fixed read-only inventory: caller identity, account summary,
IAM users, IAM roles, S3 buckets and EC2 security groups. Execution requires an
explicit account allowlist and the caller identity must match the requested
account before inventory continues.

## Exploitation and validation

V226 assesses exploitability and proof eligibility from evidence. V227 creates
finding-specific validation plans. V37 remains the actual execution guard.
Only registered, non-destructive adapters can execute in a real engagement.

## Reality over module count

The repository contains historical and policy/catalog modules as well as
operational modules. A module existing on disk is not evidence that a capability
has been exercised. Use `MODULE_STATUS.md`, execution ledgers, evidence hashes,
and test/lab results when evaluating capability maturity.


## V3.24–V3.29 reasoning layers

- **V3.24:** evidence-backed assessment intelligence and attack-path ranking.
- **V3.25:** capability catalog/runtime with deterministic bounded selection.
- **V3.26:** person-centric authorized self-assessment surface and dependency model.
- **V3.27:** adversarial reasoning with provenance, freshness, contradiction and weak-link analysis.
- **V3.28:** temporal state and digital-twin reasoning with bounded payload assurance.
- **V3.29:** unified adversary-simulation planner that combines the preceding layers,
  identifies compound weakness chains, compares perspectives, and produces governed
  validation plans without synthesizing unrestricted exploits.

The planner never infers authorization, expands scope, treats scanner output as proof,
or converts a hypothesis into an execution primitive.

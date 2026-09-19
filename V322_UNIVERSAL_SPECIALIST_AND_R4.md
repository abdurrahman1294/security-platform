# V3.22 — Universal Specialist Router & Governed R4 Capability Fabric

V3.22 connects the universal attack-surface inventory to the platform's existing specialist domains and gives R4 actions a uniform governance contract.

## Routing

All 35 universal surfaces are mapped to a registered specialist domain. Generic R0–R2 execution continues through the V3.21 ToolManager path. Domain-specific surfaces are delegated instead of being falsely marked as tested.

## R4

R4 is represented as controlled procedures: privilege-escalation validation, persistence validation, lateral-access validation, credential-access validation, objective-access validation, and controlled attack-chain validation. Each requires exact ROE permission, exact-action approval, scope revalidation, and a registered specialist or lab adapter.

The platform does **not** add unrestricted RCE, destructive impact, covert C2, uncontrolled propagation, real-data exfiltration, credential spraying at scale, carrier bypass, or arbitrary shell execution. Those remain denied capabilities.

## Perspectives

The same routing contract can be evaluated from local, LAN, enterprise, Internet IPv4/IPv6, cellular IPv4/IPv6, VPN, cloud, authenticated, administrative, testbed, and physical-lab perspectives. A perspective is an assessment origin, not an access-control bypass.

## CLI

- `fabric --action specialist-router`
- `fabric --action r4-capabilities`

Use `--authorize --execute` only when the engagement is explicitly authorized and the target is in authoritative scope. R4 still requires its separate ROE/approval mechanisms.

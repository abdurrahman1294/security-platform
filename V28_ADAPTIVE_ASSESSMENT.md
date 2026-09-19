# V2.8 Adaptive Assessment & Unusual-Target Reasoning

V2.8 changes the platform from a primarily predefined workflow into an **evidence-driven adaptive planner**.

## Loop

`observe -> classify -> hypothesize -> select bounded experiment -> re-evaluate -> escalate when needed`

## Supported reasoning paths

- Authentication/session state
- REST/OpenAPI/GraphQL/API surfaces
- Stateful workflows
- Custom/unknown protocol indicators
- Cloud identity/resource relationships
- Android/mobile artifacts
- Wireless/PCAP artifacts
- Binary/executable artifacts

## Reliability rules

1. Observations are not findings.
2. A hypothesis is not proof.
3. Existing authorization and scope always remain authoritative.
4. Unknown situations default to human escalation.
5. Experiments are planned as bounded, low-risk activities and are not auto-executed by this layer.
6. Credential guessing, arbitrary payload execution, scope expansion and high-impact automation are prohibited.
7. Tool absence is recorded as a capability limitation rather than hidden.

## Example

If evidence contains an unfamiliar TCP service, the planner can classify it as a possible custom protocol, recommend bounded characterization, and explicitly flag that deeper protocol research requires operator guidance.

# V2.4 Change Log — Adversarial Remote Security Regression Lab

V2.4 adds a dedicated Remote specialist and a disposable two-target adversarial lab.

## Remote engine
- fixed controlled proof catalog for RCE, command injection, SSRF, credential exposure, privilege escalation, persistence, lateral authentication, objective access, and destructive-boundary validation
- loopback-only lab proof execution
- explicit authorization + ROE requirement for execution
- active CLI preflight re-checks target scope
- bounded evidence output
- no arbitrary command/payload execution

## Lab
- `lab/adversarial-remote-lab/remote-target`
- `lab/adversarial-remote-lab/internal-target`
- fake credential fixture
- deterministic proof markers
- destructive-boundary fixture that proves blocking without destroying data

## Testing philosophy
The lab is intentionally vulnerable, but proof effects are disposable and deterministic. The platform is tested both for capability and for resistance to dangerous/untrusted inputs.

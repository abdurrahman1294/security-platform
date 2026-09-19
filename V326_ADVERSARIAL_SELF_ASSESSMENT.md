# V3.26 — Adversarial Self-Assessment & Chain Reasoning

V3.26 adds a person-centric assessment model for an authorized owner who wants to understand how a sophisticated adversary could chain weaknesses across their own digital footprint.

## Coverage model

The default model includes cellular connectivity, public addressing, DNS identity, email, social accounts, cloud/SaaS, computer, phone, browser, password-management boundary, recovery channels, home network/router, backups, third-party integrations and human trust boundaries.

## Reasoning

The engine builds a dependency graph and competing hypotheses rather than treating scanners as isolated truth. It considers:

- cellular IPv4/IPv6 and internet-facing exposure;
- identity and account-recovery concentration;
- endpoint → browser/session → cloud chains;
- mobile → identity/session chains;
- social/human trust → recovery/authorization chains;
- third-party integration dependencies;
- weak signals that become meaningful only when correlated;
- contradictory, stale, missing or low-quality evidence;
- cross-domain chains and alternative perspectives.

A scanner observation is never promoted automatically to “compromised”. Each hypothesis has prerequisites, supporting signals, confidence, priority, validation guidance and a bounded safety class.

## Governance

V3.26 is a reasoning and assessment-planning layer. It does not generate phishing, credential theft, persistence, covert C2, destructive actions, unrestricted RCE, carrier bypass, real exfiltration or uncontrolled propagation. Consequential validation remains behind the existing authorization, scope, ROE and approval controls.

## CLI

```text
python securityctl.py fabric --client self --target self-assessment --output-dir output/self --action self-assessment --perspective cellular_ipv6 --objective full-self-assessment
python securityctl.py fabric --client self --target self-assessment --output-dir output/self --action adversarial-matrix
```

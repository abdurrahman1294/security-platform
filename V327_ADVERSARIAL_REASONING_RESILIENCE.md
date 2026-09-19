# V3.27 — Adversarial Reasoning & Evidence Resilience

V3.27 hardens the assessment reasoning layer against the conditions that make
real investigations difficult: weak signals, contradictory observations,
stale evidence, temporal drift, source poisoning, long dependency chains,
and cross-domain trust relationships.

## Core capabilities

- Deep bounded chain enumeration across the personal attack-surface graph.
- Weak-link and uncertainty scoring.
- Independent-source corroboration scoring.
- Evidence freshness decay.
- Provenance/trust weighting.
- Contradiction preservation instead of forced resolution.
- Poisoning resistance: lower-trust observations cannot silently override
  authoritative evidence.
- Alternative reasoning paths and perspective revalidation.
- Secret-field redaction in reasoning artifacts.
- Explicit governance preservation for every generated hypothesis.

## Safety boundary

The reasoning engine is a planning and validation layer. It does not generate
credential theft, phishing, persistence, covert C2, destructive procedures,
uncontrolled propagation, carrier bypass, real-data exfiltration, or
unrestricted RCE instructions. Consequential validation remains behind the
existing authorization, scope, ROE and approval controls.

## CLI

```bash
python securityctl.py fabric --client self --target self-assessment \
  --output-dir output/self --action adversarial-reasoning \
  --objective full-self-assessment --perspective cellular_ipv6
```

Control-plane suite:

```bash
python securityctl.py fabric --client self --target self-assessment \
  --output-dir output/self --action reasoning-suite
```

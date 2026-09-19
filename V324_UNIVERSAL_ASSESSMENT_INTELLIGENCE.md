# V3.24 Universal Assessment Intelligence

V3.24 is the reasoning layer above the V3.23 execution graph. It turns observations into a coherent assessment model instead of treating findings as isolated scanner output.

## Layers
1. Cross-domain correlation
2. Evidence-quality scoring
3. State/staleness model
4. Competing hypotheses
5. Exposure-to-impact chain
6. Attack-path ranking
7. Remediation/retest loop
8. Detection-validation planning
9. Mission planning
10. Professional reporting

## Safety
The layer is planning and evidence reasoning only. It does not grant authority to exploit, persist, exfiltrate, evade, propagate, or cause destructive impact. Any active work must still pass the platform's existing scope/authorization/ROE/approval controls and registered specialist adapters.

## CLI examples

`python securityctl.py fabric --action assessment-intelligence --target 127.0.0.1 --output-dir output/v324 --objective full-assessment --baseline evidence.json`

`python securityctl.py fabric --action attack-paths --target 127.0.0.1 --output-dir output/v324 --baseline evidence.json`

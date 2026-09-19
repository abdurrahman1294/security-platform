# V3.32–V3.35 Assurance Stack

The assurance stack is the next layer after V3.31 reliability.

`V3.32 coverage → V3.33 validation → V3.34 reporting → V3.35 engine self-security`

The stack is deliberately orthogonal to offensive execution. It measures capability coverage, validates claims from evidence, reports only what the evidence supports, and audits the engine itself.

## Coverage
V3.32 answers which surface/perspective cells are assessed, capability-ready, adapter-routable, specialist-required, or still uncovered.

## Validation
V3.33 separates candidate, observed, supported, validated and impact-validated states. A scanner result is an observation/input, not automatic proof of exploitability or compromise.

## Reporting
V3.34 builds professional machine-readable reports from validated evidence, while retaining candidates and limitations.

## Self-security
V3.35 scans source code for unsafe execution patterns and secret-like literals without executing target actions.

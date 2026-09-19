# V3.56 Lab Integration Hardening

This patch closes the integration failures exposed by the isolated local lab campaign.

## Fixes

- Corrected the lab's default engine path to `security-platform-v3.56-healthcheck-patched`.
- Added explicit `--authorize` operator assertions for non-interactive pentest and bounty lab runs. The normal interactive authorization gate remains the default.
- Made recon tool selection target-aware: Subfinder/Assetfinder are skipped for IP/loopback targets because they require DNS-domain inputs.
- Corrected the tool adapter so `-d` is numeric only for Katana; Subfinder's `-d` remains a domain value.
- Allowed `AWS_ENDPOINT_URL` through the AWS tool environment so local AWS emulation cannot silently fall back to a real endpoint during the lab.
- Added the synthetic LocalStack account allowlist to the lab runner.
- Added a deterministic bundled Nuclei lab template fallback. It is copied into the engagement evidence root before execution and contains only a benign marker-detection check.
- Improved LocalStack readiness handling with a bounded wait and container diagnostics on failure.
- Removed the obsolete Compose `version` key from the lab stack.

## Safety properties retained

The patch does not introduce arbitrary shell execution, unrestricted Nuclei template execution, scope expansion, credential dumping, persistence deployment, or unrestricted remote control. Active testing remains scope-checked and authorization-controlled.

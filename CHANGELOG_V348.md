# V3.48 Multi-Target Integration Range

V3.48 upgrades the local validation environment from a single mixed fixture set to a multi-target range with 16 independent representative targets and 36 seeded vulnerability scenarios.

Key properties:
- Discovery executes before the hidden ground-truth manifest is opened.
- Web/API and network targets are exposed through disposable loopback services.
- Identity, cloud, endpoint, mobile, wireless, firmware/IoT, OT/ICS, automotive, containers, source/supply-chain, reverse engineering, data, AI/ML, and telecom targets expose synthetic assessment interfaces.
- Results include per-target accounting and black-box evidence provenance.
- A hardened control fixture is present to preserve a negative-test boundary.
- No external hosts, real credentials, destructive actions, persistence, covert C2, propagation, or unrestricted RCE are used.

This remains a validation range, not proof of universal real-world pentesting coverage. External specialist tools and real operating-system/device ranges remain separate integration work.

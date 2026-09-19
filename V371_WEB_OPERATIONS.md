# V3.71 Web Operations Upgrade

V3.71 turns the V3.70 local browser wrapper into an interactive operations workspace.

## Added
- WebSocket live mission telemetry.
- Attack-path visualization backed by V3.67 attack-path intelligence.
- Direct rare-case analysis endpoint.
- Persistent security conversation endpoint.
- Specialist-loop timeline and run statistics.
- Evidence count/refresh view.
- Responsive browser/mobile layout.
- Backend version 3.71.

## Reasoning integration
The V3.69 specialist loop now invokes the actual V3.67 attack-path and rare-case engines instead of treating those specialists as metadata-only categories.

## Boundary
The browser never becomes the authority layer. Backend scope, authorization, approvals, named capabilities and evidence controls remain authoritative. No arbitrary shell endpoint is introduced.

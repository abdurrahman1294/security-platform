# V3.19 — Universal Cellular Assessment Fabric

## Purpose

V3.19 makes cellular/mobile-data connectivity a first-class **assessment origin** for every specialist domain. It does not make LAN-only services magically reachable: the target must expose an approved Internet/mobile-network path, an approved external API, or an approved testbed path.

## Research-derived design decisions

- **CGNAT-aware:** IPv4 carrier NAT is a common topology and is outside subscriber control; failure to receive inbound traffic is therefore an exposure observation, not a proof that the target is secure. RFC 6888 describes CGN as an ISP-side NAT that shares IPv4 addresses among subscribers.
- **IPv6-first comparison:** cellular IPv6 can create a materially different reachability model, so IPv4 and IPv6 are separate evidence dimensions.
- **5G architecture-aware:** the cellular perspective records access, network, user, application and service-based-architecture context instead of treating 5G as simply another Wi-Fi network.
- **Mobile-app network testing:** OWASP MASVS/MAS TG require explicit testing of secure network communication, endpoint identity/pinning, and dynamic/static/network perspectives. These become cellular-origin test dimensions where the backend is externally reachable.
- **Managed mobile devices:** Apple management is a distinct authorized channel and does not imply arbitrary device access.

## Universal domain coverage

Every domain gets a cellular-origin entry: web/API, infrastructure, network, identity, cloud, wireless gateways, mobile, remote computer, remote mobile, firmware/digital twins, OT/ICS gateways/testbeds, automotive telematics/testbeds, IoT, network devices, OSINT and reporting.

The universal rule is:

> Cellular is an origin, not an authority or a bypass.

A domain remains inaccessible from cellular when it is intentionally LAN-only, carrier-filtered, behind CGNAT without an inbound path, or otherwise not exposed. The engine records that as `unreachable-from-cellular` rather than routing around the boundary.

## Probe operations

The portable cellular probe supports only bounded operations:

- source characterization
- exact-host DNS resolution
- exact-host:port TCP connectivity
- exact-host:port TLS handshake
- exact approved HTTP(S) request
- comparison with a baseline observation

TCP/TLS tests require an explicit port allowlist. HTTP tests require an exact target-matching URL. There is no recursive discovery, covert tunnel, arbitrary command execution, credential capture, carrier-control bypass, or uncontrolled scan.

## Operational model

1. Run the probe on a host actually using cellular data (phone tether, cellular laptop, modem/router, or approved remote probe).
2. Record source identity and timestamp.
3. Test the exact approved target/ports/URLs.
4. Import the evidence into the platform.
5. Correlate cellular results with LAN/enterprise/VPN baselines.
6. Route findings to the same specialist engines and evidence graph.
7. Retest from the same cellular origin after remediation.

## What cellular can and cannot test

### Can test when exposed

- public web/API services
- public IPv4/IPv6 services
- remote administration interfaces intentionally exposed to the Internet
- mobile backends
- cloud endpoints
- telematics APIs
- externally reachable IoT gateways
- externally reachable network-device management surfaces
- approved VPN/overlay endpoints
- approved digital-twin/testbed services

### Cannot be assumed reachable

- private RFC1918-only services
- LAN-only SMB/WinRM/SSH
- devices behind inbound-blocking CGNAT
- carrier-filtered ports
- iOS internal filesystem/debug surfaces without an approved instrumented channel
- physical JTAG/SWD/CAN interfaces merely because the target also has cellular connectivity

## Security boundary

All V3.15–V3.18 specialist controls remain in force. A cellular observation never grants authorization to another module. Active validation still requires the existing scope, ROE, ToolManager and approval controls.

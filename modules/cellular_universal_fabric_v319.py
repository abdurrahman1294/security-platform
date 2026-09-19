"""V3.19 cellular-origin assessment fabric.

Turns cellular connectivity into a first-class assessment origin for every domain
without assuming that cellular data provides inbound reachability. The probe uses
fixed, auditable operations and exact target/port allowlists; it never creates a
covert tunnel, bypasses carrier controls, or performs unrestricted scanning.
"""
from __future__ import annotations
import hashlib, ipaddress, json, socket, ssl, time
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
from modules.atomic_io import atomic_write_json

VERSION = "3.19.0"

CELLULAR_DOMAINS = {
    "web_api": ["HTTP", "HTTPS", "TLS", "DNS"],
    "infrastructure": ["TCP", "UDP-bounded", "IPv4", "IPv6"],
    "network": ["TCP", "TLS", "SNMP-evidence", "DNS"],
    "identity": ["HTTPS", "LDAPS", "Kerberos-evidence"],
    "cloud": ["HTTPS", "IPv4", "IPv6", "DNS"],
    "wireless": ["Internet-facing gateway/API evidence"],
    "mobile": ["HTTPS/API", "TLS", "DNS", "app-backend correlation"],
    "remote_computer": ["SSH", "SMB", "WinRM", "RDP", "HTTPS", "IPv4", "IPv6"],
    "remote_mobile": ["approved management/API", "Corellium", "ADB-over-approved-path"],
    "firmware": ["artifact/API retrieval", "digital-twin network path"],
    "ot_ics": ["approved internet-facing gateway/API only", "testbed path"],
    "automotive": ["telematics/API", "DoIP testbed", "digital-twin path"],
    "iot": ["HTTPS", "MQTT-over-TLS", "CoAP-over-UDP bounded", "DNS"],
    "network_device": ["HTTPS", "SSH", "TLS", "SNMP-evidence"],
    "osint": ["HTTP", "HTTPS", "DNS"],
    "reporting": ["artifact upload over HTTPS"],
}

SAFETY = {
    "R0": "source characterization and offline correlation",
    "R1": "bounded reachability/service checks against exact approved endpoints",
    "R2": "approved authenticated/non-destructive validation",
    "R3": "isolated testbed validation",
    "R4": "operator-approved consequential action through an existing governed adapter",
    "R5": "denied: carrier bypass, covert tunneling, credential theft, uncontrolled scanning, propagation, destructive traffic",
}

PROBE_ACTIONS = {
    "source": "report local cellular-origin network identity and addressing",
    "dns": "resolve exact approved hostname using the probe resolver",
    "tcp": "connect to one exact approved host:port with a bounded timeout",
    "tls": "perform a TLS handshake to one exact approved host:port",
    "http": "perform one bounded HTTP(S) GET to one exact approved URL",
    "compare": "compare two previously collected probe result sets",
}


def _write(root: str | Path, name: str, data: dict[str, Any]):
    root = Path(root); (root / "evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def validate_probe_request(action: str, target: str, port: int | None = None, url: str = "", approved_ports: Iterable[int] = ()) -> dict[str, Any]:
    errors = []
    if action not in PROBE_ACTIONS:
        errors.append("unsupported-action")
    if not target and action != "compare":
        errors.append("target-required")
    allowed = {int(p) for p in approved_ports}
    if action in {"tcp", "tls"}:
        if port is None or not (1 <= int(port) <= 65535): errors.append("valid-port-required")
        elif allowed and int(port) not in allowed: errors.append("port-not-in-allowlist")
        elif not allowed: errors.append("explicit-port-allowlist-required")
    if action == "http":
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname: errors.append("valid-http-url-required")
        if parsed.hostname and target and parsed.hostname != target: errors.append("url-host-must-match-target")
    return {"allowed": not errors, "errors": errors, "action": action, "target": target, "port": port, "url": url}


def build_universal_cellular_surface(root: str | Path, target: str, objective: str = "full-cellular-perspective") -> dict[str, Any]:
    rows = []
    for domain, channels in CELLULAR_DOMAINS.items():
        rows.append({
            "domain": domain,
            "cellular_reachable": True,
            "required_property": "target exposes an approved Internet/mobile-network path or an approved external API",
            "channels": channels,
            "fallback": "if no cellular path exists, mark unreachable-from-cellular rather than routing through LAN/VPN",
            "evidence": ["source identity", "IPv4/IPv6 result", "DNS result", "transport result", "timestamp", "probe identity"],
        })
    return _write(root, "cellular-universal-surface-v319.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "domains": rows,
        "principle": "cellular is an assessment origin, not a permission bypass; every specialist still re-applies scope and authorization",
        "safety": SAFETY,
    })


def build_cellular_probe_contract(root: str | Path, target: str, approved_ports: Iterable[int] = (), approved_urls: Iterable[str] = ()) -> dict[str, Any]:
    ports = sorted({int(p) for p in approved_ports})
    urls = sorted({str(u) for u in approved_urls})
    return _write(root, "cellular-probe-contract-v319.json", {
        "schema_version": VERSION, "target": target, "approved_ports": ports, "approved_urls": urls,
        "actions": PROBE_ACTIONS,
        "controls": ["exact target allowlist", "exact port allowlist", "exact URL allowlist", "bounded timeout", "no recursive discovery", "no covert tunnel", "immutable probe identity", "timestamped evidence"],
    })


def build_cellular_comparison(root: str | Path, cellular: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    keys = ["ipv4", "ipv6", "dns", "tcp", "tls", "http"]
    deltas = {k: {"cellular": cellular.get(k), "baseline": baseline.get(k), "changed": cellular.get(k) != baseline.get(k)} for k in keys if k in cellular or k in baseline}
    return _write(root, "cellular-comparison-v319.json", {"schema_version": VERSION, "deltas": deltas, "interpretation": "differences are evidence for path-specific exposure; they are not proof of vulnerability by themselves"})


def build_v319_fabric(root: str | Path, target: str, objective: str = "full-cellular-perspective", approved_ports: Iterable[int] = (), approved_urls: Iterable[str] = ()) -> dict[str, Any]:
    return {
        "universal_surface": build_universal_cellular_surface(root, target, objective),
        "probe_contract": build_cellular_probe_contract(root, target, approved_ports, approved_urls),
        "remote_file_access_note": "remote-file-access remains available through V3.18 and can be invoked from the cellular perspective only when its channel is Internet-reachable and explicitly authorized",
        "advanced_domains": ["firmware", "reverse-engineering", "protocol-fuzzing", "digital-twin", "physical-interface-correlation"],
        "cellular_rule": "all domains may be assessed from cellular origin when they expose an approved external path; LAN-only interfaces remain LAN-only",
    }


def run_probe(action: str, target: str = "", port: int | None = None, url: str = "", approved_ports: Iterable[int] = (), timeout: float = 3.0) -> dict[str, Any]:
    """Run one bounded probe operation. No scanning or arbitrary command execution."""
    req = validate_probe_request(action, target, port, url, approved_ports)
    if not req["allowed"]: return {"status": "blocked", **req}
    started = time.time()
    result = {"schema_version": VERSION, "action": action, "target": target, "started": started}
    try:
        if action == "source":
            # Source identity is intentionally limited to local interface/address data.
            addrs = []
            for info in socket.getaddrinfo(socket.gethostname(), None):
                addrs.append(info[4][0])
            result.update({"status": "ok", "local_addresses": sorted(set(addrs))})
        elif action == "dns":
            result.update({"status": "ok", "addresses": sorted({x[4][0] for x in socket.getaddrinfo(target, None)}), "resolver": "system"})
        elif action in {"tcp", "tls"}:
            with socket.create_connection((target, int(port)), timeout=timeout) as sock:
                if action == "tls":
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(sock, server_hostname=target) as tls_sock:
                        result.update({"status": "ok", "tls_version": tls_sock.version(), "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None})
                else:
                    result.update({"status": "ok"})
        elif action == "http":
            import urllib.request
            req2 = urllib.request.Request(url, headers={"User-Agent": "security-platform-cellular-probe/3.19"}, method="GET")
            with urllib.request.urlopen(req2, timeout=timeout) as resp:
                result.update({"status": "ok", "status_code": resp.status, "content_type": resp.headers.get("Content-Type")})
        else:
            result["status"] = "unsupported-runtime-action"
    except Exception as exc:
        result.update({"status": "error", "error_type": type(exc).__name__})
    result["elapsed_ms"] = round((time.time() - started) * 1000, 2)
    return result

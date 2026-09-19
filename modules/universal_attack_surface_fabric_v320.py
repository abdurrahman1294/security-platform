"""V3.20 universal attack-surface and assessment-perspective fabric.

This module turns attack-surface categories into executable, governed assessment
workflows. It deliberately separates *what can be assessed* from *what authority
exists to assess it*. Safe execution is routed through the existing ToolManager;
no alternate shell or arbitrary command path is introduced.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Any, Iterable
from modules.atomic_io import atomic_write_json

VERSION = "3.20.0"

# A deliberately broad asset/surface taxonomy. Categories are assessment objects,
# not claims that every target contains every surface.
ATTACK_SURFACES: dict[str, dict[str, Any]] = {
    "external_web": {"family":"application", "assets":["websites","virtual-hosts","admin-portals","CDN/edge"], "tests":["discovery","tls","headers","content","auth","authorization","input-validation","business-logic"]},
    "api": {"family":"application", "assets":["REST","GraphQL","SOAP","gRPC","webhooks"], "tests":["inventory","authentication","object-authorization","function-authorization","property-authorization","rate-limits","ssrf","misconfiguration","unsafe-consumption"]},
    "dns_certificate": {"family":"internet", "assets":["DNS","DNSSEC","certificates","CT","CAA","MX"], "tests":["records","delegation","zone-transfer-evidence","certificate-scope","expiration","misconfiguration"]},
    "internet_services": {"family":"infrastructure", "assets":["TCP/UDP services","IPv4","IPv6","edge appliances"], "tests":["reachability","service-fingerprint","version","tls","exposure-diff"]},
    "remote_access": {"family":"endpoint", "assets":["SSH","RDP","SMB","WinRM","VPN","remote-admin"], "tests":["reachability","authentication","configuration","authorization","file-access","session-controls"]},
    "endpoint_windows": {"family":"endpoint", "assets":["Windows hosts","services","drivers","Defender/EDR"], "tests":["software","patch","services","local-policy","firewall","identity","security-controls"]},
    "endpoint_linux": {"family":"endpoint", "assets":["Linux hosts","daemons","systemd","containers"], "tests":["software","patch","services","permissions","sudo-policy","firewall","identity"]},
    "endpoint_macos": {"family":"endpoint", "assets":["macOS hosts","launch services","security controls"], "tests":["software","patch","services","privacy-controls","identity","network"]},
    "identity_directory": {"family":"identity", "assets":["AD","LDAP","IdP","SSO","Kerberos","RADIUS","TACACS+"], "tests":["authentication","authorization","trusts","delegation","MFA","session","privilege-paths"]},
    "cloud": {"family":"cloud", "assets":["AWS","Azure","GCP","IAM","storage","serverless","metadata"], "tests":["inventory","IAM","network","storage","secrets","logging","public-exposure","cross-account"]},
    "saas": {"family":"cloud", "assets":["SaaS tenants","admin consoles","OAuth apps","service principals"], "tests":["SSO","OAuth","roles","tenant-isolation","sharing","API","audit"]},
    "containers": {"family":"platform", "assets":["Docker","OCI","Kubernetes","registries","kubelets"], "tests":["inventory","RBAC","network","secrets","image-risk","runtime","escape-boundaries"]},
    "virtualization": {"family":"platform", "assets":["VMware","Hyper-V","ESXi","management planes"], "tests":["management-exposure","auth","segmentation","version","configuration"]},
    "network_devices": {"family":"network", "assets":["routers","switches","firewalls","WAF","load-balancers","APs"], "tests":["management","SNMP","SSH","TLS","ACL","routing","firmware","segmentation"]},
    "wireless": {"family":"wireless", "assets":["Wi-Fi","BLE","802.15.4","wireless gateways"], "tests":["inventory","encryption","authentication","configuration","passive-analysis","gateway-exposure"]},
    "mobile_android": {"family":"mobile", "assets":["APK","AAB","Android device","ADB","mobile APIs"], "tests":["static","permissions","components","crypto","storage","runtime","network","API"]},
    "mobile_ios": {"family":"mobile", "assets":["IPA","iOS device","simulator","Corellium","mobile APIs"], "tests":["static","entitlements","signing","storage","runtime","network","API"]},
    "iot": {"family":"embedded", "assets":["smart devices","gateways","MQTT","CoAP","UPnP"], "tests":["discovery","management","firmware","protocol","cloud","segmentation"]},
    "firmware": {"family":"embedded", "assets":["firmware images","bootloaders","update packages","filesystem"], "tests":["extraction","SBOM","secrets","crypto","signing","rollback","binary-analysis","emulation"]},
    "hardware_debug": {"family":"hardware", "assets":["JTAG","SWD","UART","SPI","I2C","USB","PCIe","TPM"], "tests":["inventory","lock-state","configuration","evidence-capture","correlation"]},
    "ot_ics": {"family":"ot", "assets":["PLCs","HMIs","SCADA","historians","engineering stations"], "tests":["asset-inventory","protocol","segmentation","authentication","configuration","safe-validation"]},
    "automotive": {"family":"automotive", "assets":["ECUs","CAN/CAN-FD","UDS","DoIP","SOME/IP","telematics"], "tests":["bus-analysis","diagnostic-surface","gateway","firmware","telematics","digital-twin"]},
    "databases": {"family":"data", "assets":["SQL","NoSQL","cache","search","message stores"], "tests":["exposure","authentication","authorization","configuration","TLS","backup"]},
    "storage_backup": {"family":"data", "assets":["object storage","file shares","backup","snapshots"], "tests":["public-exposure","ACL","encryption","retention","restore","cross-tenant"]},
    "email_collaboration": {"family":"identity", "assets":["SMTP","M365","Google Workspace","mail gateways","collaboration"], "tests":["SPF","DKIM","DMARC","auth","sharing","OAuth","external-forwarding"]},
    "supply_chain": {"family":"software", "assets":["dependencies","packages","registries","SBOM","signing"], "tests":["dependency-risk","provenance","signing","typosquat-evidence","secrets","update-chain"]},
    "source_code_ci_cd": {"family":"software", "assets":["Git","CI/CD","build runners","artifacts","secrets"], "tests":["branch-protection","secrets","runner-isolation","artifact-integrity","permissions","webhooks"]},
    "secrets_keys": {"family":"data", "assets":["API keys","tokens","certificates","vaults","KMS/HSM"], "tests":["exposure","rotation","scope","storage","access-policy"]},
    "observability_management": {"family":"management", "assets":["SIEM","EDR","RMM","MDM","monitoring","deployment tools"], "tests":["exposure","RBAC","API","logging","control-paths","segmentation"]},
    "third_party_integrations": {"family":"supply-chain", "assets":["webhooks","OAuth integrations","partner APIs","managed services"], "tests":["trust","authentication","authorization","webhook-validation","data-sharing","failure-modes"]},
    "client_browser_desktop": {"family":"client", "assets":["browsers","desktop apps","extensions","Office/PDF"], "tests":["update","extension","local-storage","network","trust-boundary","content-handling"]},
    "human_social": {"family":"human", "assets":["identity processes","helpdesk","recovery flows","operator workflows"], "tests":["process-review","MFA-recovery","approval-boundaries","social-engineering-resilience"], "execution":"human-led/lab-only"},
    "physical_facility": {"family":"physical", "assets":["ports","console access","badging","equipment rooms"], "tests":["physical-review","port-access","device-tamper","environmental-controls"], "execution":"onsite-authorized"},
    "ai_ml": {"family":"application", "assets":["LLM apps","agents","RAG","model APIs","plugins/tools"], "tests":["prompt-boundaries","data-isolation","tool-authorization","retrieval-controls","model/API auth","output handling"], "execution":"bounded/application-level"},
    "cellular_telecom": {"family":"telecom", "assets":["IPv4/IPv6 mobile paths","APN","carrier edge","mobile backends","5G-facing APIs"], "tests":["reachability","dual-stack","DNS","TLS","API","path-difference"], "execution":"external-probe/authorized-carrier-testbed"},
}

PERSPECTIVES = {
    "local_host": "same-host/local observation",
    "physical_adjacent": "directly attached/physical lab",
    "lan": "same broadcast/routed LAN",
    "enterprise": "segmented enterprise vantage",
    "internet_ipv4": "public IPv4 vantage",
    "internet_ipv6": "public IPv6 vantage",
    "cellular_ipv4": "mobile-data IPv4 vantage",
    "cellular_ipv6": "mobile-data IPv6 vantage",
    "vpn": "authorized VPN/overlay vantage",
    "cloud_vantage": "authorized cloud-region vantage",
    "authenticated_user": "authorized low-privilege authenticated vantage",
    "admin_authenticated": "authorized administrative vantage",
    "testbed": "isolated digital-twin/testbed vantage",
    "physical_lab": "authorized hardware/vehicle/OT lab vantage",
}

# Mapping from surface to safe, already-registered executable specialists.
EXECUTION_ADAPTERS = {
    "external_web": ["subfinder", "httpx", "katana", "nuclei"],
    "api": ["httpx", "nuclei"],
    "dns_certificate": ["subfinder", "httpx"],
    "internet_services": ["naabu", "nmap"],
    "network_devices": ["nmap", "httpx"],
    "cloud": ["aws", "az", "gcloud"],
    "containers": ["kubectl"],
    "identity_directory": ["nxc"],
    "remote_access": ["nmap", "nxc"],
    "cellular_telecom": ["nmap", "httpx"],
}

SAFE_EXECUTION_CLASSES = {"R0_observe", "R1_bounded_discovery", "R2_non_destructive_verify"}
DENIED_AUTONOMOUS_CLASSES = {"credential_theft", "unrestricted_rce", "persistence", "propagation", "destructive_impact", "covert_c2", "carrier_bypass"}


def _write(root: str | Path, name: str, data: dict[str, Any]):
    root = Path(root); (root / "evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def _hash(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def build_attack_surface_inventory(root: str | Path, *, target: str, observed: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    observed_rows = list(observed)
    assets = []
    for sid, spec in ATTACK_SURFACES.items():
        matches = [o for o in observed_rows if str(o.get("surface", "")) == sid or str(o.get("family", "")) == spec["family"]]
        assets.append({
            "surface_id": sid, "family": spec["family"], "assets": spec["assets"],
            "tests": spec["tests"], "observed_evidence": matches,
            "status": "observed" if matches else "candidate",
            "execution_mode": spec.get("execution", "governed-specialist"),
        })
    return _write(root, "attack-surface-inventory-v320.json", {
        "schema_version": VERSION, "target": target, "surface_count": len(assets),
        "surfaces": assets,
        "principle": "inventory is hypothesis-driven; candidate surfaces require evidence before active validation",
    })


def build_perspective_matrix(root: str | Path, *, target: str, surfaces: Iterable[str] | None = None) -> dict[str, Any]:
    selected = list(surfaces) if surfaces else list(ATTACK_SURFACES)
    rows = []
    for sid in selected:
        if sid not in ATTACK_SURFACES:
            continue
        for pid, description in PERSPECTIVES.items():
            # Reachability is intentionally unknown until observed; cellular is
            # available wherever an approved Internet/mobile path exists.
            mode = "conditional"
            if pid in {"testbed", "physical_lab"} and ATTACK_SURFACES[sid]["family"] not in {"embedded", "hardware", "ot", "automotive", "physical"}:
                mode = "optional"
            rows.append({"surface": sid, "perspective": pid, "description": description, "reachability": mode})
    return _write(root, "perspective-matrix-v320.json", {"schema_version": VERSION, "target": target, "rows": rows})


def build_factor_graph(root: str | Path, *, target: str) -> dict[str, Any]:
    factors = [
        "asset_exposure", "addressing_ipv4_ipv6", "network_path", "trust_boundary", "identity", "authentication", "authorization",
        "software_version", "configuration", "protocol_state", "crypto", "secrets", "dependencies", "supply_chain", "management_plane",
        "remote_access", "physical_access", "human_process", "data_sensitivity", "third_party_trust", "cloud_control_plane", "container_runtime",
        "mobile_permissions", "firmware_update_chain", "debug_interfaces", "telemetry_detection", "backup_recovery", "segmentation", "time/state",
    ]
    edges = []
    for a in factors:
        for b in factors:
            if a == b:
                continue
            if {a,b} in [
                {"asset_exposure","network_path"}, {"identity","authorization"}, {"software_version","dependencies"},
                {"management_plane","remote_access"}, {"firmware_update_chain","software_version"}, {"debug_interfaces","physical_access"},
                {"cloud_control_plane","identity"}, {"container_runtime","segmentation"}, {"telemetry_detection","management_plane"},
                {"backup_recovery","data_sensitivity"}, {"mobile_permissions","authorization"}, {"supply_chain","dependencies"},
            ]:
                edges.append({"from": a, "to": b, "relationship": "security-factor"})
    return _write(root, "attack-surface-factor-graph-v320.json", {"schema_version": VERSION, "target": target, "factors": factors, "edges": edges})


def build_functional_assessment_plan(root: str | Path, *, target: str, perspective: str = "internet_ipv4", requested_surfaces: Iterable[str] | None = None, authorized: bool = False) -> dict[str, Any]:
    selected = list(requested_surfaces) if requested_surfaces else list(ATTACK_SURFACES)
    steps = []
    for sid in selected:
        spec = ATTACK_SURFACES.get(sid)
        if not spec:
            continue
        adapters = EXECUTION_ADAPTERS.get(sid, [])
        steps.append({
            "step_id": "AS-" + _hash(target, perspective, sid),
            "surface": sid, "perspective": perspective, "family": spec["family"],
            "tests": spec["tests"], "adapters": adapters,
            "execution_class": "R1_bounded_discovery" if adapters else "specialist_or_artifact",
            "requires_authorization": True,
            "authorized": bool(authorized),
            "status": "ready-for-governed-execution" if authorized else "plan-only",
        })
    return _write(root, "functional-assessment-plan-v320.json", {
        "schema_version": VERSION, "target": target, "perspective": perspective,
        "authorized": bool(authorized), "steps": steps,
        "denied_autonomous_classes": sorted(DENIED_AUTONOMOUS_CLASSES),
        "execution_rule": "all active execution routes through the existing ToolManager or specialist lab adapter; this fabric creates no alternate command path",
    })


def build_v320_fabric(root: str | Path, *, target: str, perspective: str = "internet_ipv4", authorized: bool = False, observed: Iterable[dict[str, Any]] = (), requested_surfaces: Iterable[str] | None = None) -> dict[str, Any]:
    return {
        "attack_surface_inventory": build_attack_surface_inventory(root, target=target, observed=observed),
        "perspective_matrix": build_perspective_matrix(root, target=target, surfaces=requested_surfaces),
        "factor_graph": build_factor_graph(root, target=target),
        "functional_plan": build_functional_assessment_plan(root, target=target, perspective=perspective, requested_surfaces=requested_surfaces, authorized=authorized),
        "version": VERSION,
        "coverage": {"surface_count": len(ATTACK_SURFACES), "perspective_count": len(PERSPECTIVES), "execution_adapters": sorted({x for v in EXECUTION_ADAPTERS.values() for x in v})},
    }

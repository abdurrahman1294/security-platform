from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json

VERSION = "300.0"

CAPABILITIES = {
    "web": ["discovery", "http-probing", "technology-fingerprinting", "crawling", "vulnerability-discovery", "authentication", "authorization", "session", "input-validation", "client-side", "business-logic", "workflow", "tls", "misconfiguration", "evidence", "manual-review"],
    "api": ["REST", "OpenAPI", "GraphQL", "authentication", "BOLA", "function-authorization", "property-authorization", "rate-limits", "SSRF", "schema-exposure", "inventory", "business-flows"],
    "infrastructure": ["DNS", "subdomains", "ports", "services", "versions", "TLS", "management-interfaces", "network-services", "CVE-correlation", "exposure-analysis"],
    "network": ["host-discovery", "service-discovery", "segmentation", "SMB", "RDP", "SSH", "LDAP", "Kerberos", "WinRM", "databases", "database-surface-analysis", "network-device-exposure", "network-device-config-review"],
    "ad": ["domain-structure", "users", "groups", "computers", "shares", "password-policy", "SPNs", "ACLs", "delegation", "trusts", "privilege-paths", "read-only-enumeration"],
    "aws": ["identity", "IAM-relationships", "S3", "EC2", "security-groups", "VPC", "public-exposure", "role-trust", "least-privilege", "configuration-evidence", "read-only-inventory"],
    "cloud": ["AWS", "Azure", "GCP", "Kubernetes", "container-security", "container-image-static-analysis", "identity", "storage", "networking", "public-exposure", "configuration"],
    "osint": ["infrastructure", "web", "code", "documents", "organization", "social", "media", "images", "history", "correlation", "provenance", "gap-analysis"],
    "bug_bounty": ["program-policy", "scope", "recon", "asset-prioritization", "web", "API", "auth", "authorization", "logic", "client-side", "cloud", "triage", "deduplication", "evidence", "report-preparation", "human-submission"],
    "android_mobile": ["APK acquisition", "manifest", "permissions", "exported-components", "WebView", "cleartext", "backup", "debuggable", "secret-marker detection", "native libraries", "read-only emulator inspection", "dynamic-analysis handoff"],
    "ios_mobile": ["IPA metadata", "ATS review", "Mach-O presence", "URL inventory", "redacted secret markers", "simulator app inventory", "simulator process inventory", "bounded runtime marker analysis", "offline runtime export analysis"],
    "wireless": ["Wi-Fi interface inventory", "driver/radio capability observation", "passive capture planning", "PCAP analysis", "SSID/BSSID/channel inventory", "rogue-AP analysis", "segmentation validation", "BLE planning"],
    "orchestration": ["mission-planning", "evidence-fabric", "adaptive-next-steps", "continuous-diff", "resumable-engagement", "asset-criticality", "multi-hop-attack-paths", "confidence-calibration", "provenance-chain", "dependency-aware-remediation", "authenticated-session-model", "plugin-contracts", "coverage-scoring", "multi-role-agentic-planning", "parallel-dependency-scheduling", "context-manifest-and-resume", "source-runtime-correlation", "browser-trace-evidence", "continuous-assurance", "benchmark-quality-metrics", "provider-agnostic-model-routing", "ATT&CK-emulation-planning"],
    "ecosystem_integration": ["ProjectDiscovery", "Metasploit", "Sliver", "Havoc", "Impacket", "NetExec", "BloodHound", "MobSF", "Frida", "Hashcat", "Responder", "Semgrep/CodeQL-SARIF", "browser-proxy/HAR evidence", "offline-evidence-import", "capability-gap-matrix", "cross-ecosystem-correlation"],
    "reporting": ["executive", "technical", "attack-path", "evidence", "remediation", "retest", "coverage", "limitations"],
}

def build(root: str | Path, *, target: str = "", tool_inventory=None) -> dict:
    root = Path(root)
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    inventory = tool_inventory or []
    data = {
        "schema_version": VERSION,
        "target": target,
        "capabilities": {k: list(v) for k, v in CAPABILITIES.items()},
        "tool_inventory": inventory,
        "coverage_rule": "Only executed, evidence-backed work counts as covered; plans and checklists do not count as execution.",
        "completion_rule": "A domain is complete only when applicable discovery, assessment, evidence, verification, limitations and human-review requirements are satisfied.",
        "known_non_automatable": ["business-logic judgment", "application-specific workflow interpretation", "final attribution", "final vulnerability confirmation where evidence is insufficient"],
    }
    atomic_write_json(evidence / "capability-matrix-v300.json", data)
    return data

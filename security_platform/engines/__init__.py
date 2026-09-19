from .pentest import PentestEngine
from .osint import OSINTEngine
from .bounty import BugBountyEngine
from .mobile import MobileEngine
from .wireless import WirelessEngine
from .remote import RemoteEngine
from security_platform.core.registry import register, EngineSpec

register(EngineSpec(
    "bounty", "Program-aware bug-bounty research and triage", BugBountyEngine,
    True, "3.2", ("program-policy", "scope", "research", "recon", "web", "api", "auth", "authorization", "logic", "triage", "evidence", "report-readiness")
))
register(EngineSpec(
    "osint", "Public-source intelligence collection and correlation", OSINTEngine,
    True, "3.2", ("public-collection", "normalization", "correlation", "gap-analysis", "provenance", "research-exhaustion")
))
register(EngineSpec(
    "pentest", "Authorized technical security assessment", PentestEngine,
    True, "3.2", ("recon", "web", "api", "network", "infrastructure", "host", "active-directory", "aws", "azure", "gcp", "kubernetes", "cloud", "authentication", "authorization", "validation", "evidence", "coverage", "reporting", "mobile", "wireless", "artifact-integrity", "cross-engine-correlation", "run-state", "health")
))

register(EngineSpec(
    "mobile", "Android/mobile application security assessment", MobileEngine,
    True, "3.2", ("android", "apk-static", "manifest", "ios", "ipa-static", "permissions", "exported-components", "webview", "secrets", "native-libraries", "readonly-device-inspection", "artifact-analysis", "coverage-evidence")
))
register(EngineSpec(
    "wireless", "Wireless security assessment and passive radio/PCAP analysis", WirelessEngine,
    True, "3.2", ("wifi", "interface-inventory", "ble", "ble-passive", "radio-capabilities", "passive-analysis", "pcap", "rogue-ap-analysis", "bluetooth-planning", "pcap-evidence", "passive-correlation")
))

register(EngineSpec(
    "remote", "Authorized remote-system assessment and controlled lab proof validation", RemoteEngine,
    True, "3.2", ("remote-services", "rce-validation", "command-injection", "credential-exposure", "privilege-escalation", "persistence-validation", "lateral-path", "objective-access", "destructive-boundary", "evidence-state", "controlled-regression")
))

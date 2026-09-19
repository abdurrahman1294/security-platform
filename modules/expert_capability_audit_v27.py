from __future__ import annotations
from pathlib import Path
from typing import Any
from .atomic_io import atomic_write_json, load_json

VERSION = "2.7"

# This catalog deliberately separates technical capability from activities that
# require a human operator, special hardware, or explicit high-impact ROE.
CAPABILITY_CATALOG: dict[str, list[dict[str, Any]]] = {
    "pre_engagement": [
        {"id":"pre.scope", "name":"scope and authorization validation", "mode":"native", "evidence":[]},
        {"id":"pre.roe", "name":"rules-of-engagement validation", "mode":"native", "evidence":["config_roe.example.json"]},
        {"id":"pre.toolchain", "name":"toolchain readiness assessment", "mode":"native", "evidence":["evidence/engine-health-v26.json"]},
        {"id":"pre.objectives", "name":"assessment objective and test-plan definition", "mode":"human-assisted", "evidence":[]},
    ],
    "reconnaissance": [
        {"id":"recon.subdomains", "name":"subdomain/asset discovery", "mode":"tool-backed", "tools":["subfinder","assetfinder"], "evidence":["recon/subdomains.txt"]},
        {"id":"recon.http", "name":"HTTP service discovery and fingerprinting", "mode":"tool-backed", "tools":["httpx"], "evidence":["recon/live-hosts.txt"]},
        {"id":"recon.ports", "name":"port and service discovery", "mode":"tool-backed", "tools":["naabu","nmap"], "evidence":["ports/naabu.txt","ports/nmap-detailed.nmap","ports/nmap-top.nmap"]},
        {"id":"recon.webcrawl", "name":"web crawling and URL inventory", "mode":"tool-backed", "tools":["katana"], "evidence":["web/urls.txt"]},
        {"id":"recon.dns", "name":"DNS/address observation", "mode":"native", "evidence":["evidence/dns-observation-v27.json"]},
        {"id":"recon.attack_surface", "name":"cross-source attack-surface normalization", "mode":"native", "evidence":["evidence/cross-engine-correlation-v26.json"]},
    ],
    "web_api": [
        {"id":"web.vuln", "name":"automated web vulnerability discovery", "mode":"tool-backed", "tools":["nuclei"], "evidence":["vulns/findings.json","vulns/findings.txt"]},
        {"id":"web.auth", "name":"authenticated web assessment", "mode":"native", "evidence":["web/authenticated"]},
        {"id":"web.session", "name":"session security assessment", "mode":"native", "evidence":[]},
        {"id":"web.client", "name":"client-side security heuristics", "mode":"native", "evidence":[]},
        {"id":"web.logic", "name":"business-logic and workflow assessment", "mode":"human-assisted", "evidence":[]},
        {"id":"api.rest", "name":"REST/API surface assessment", "mode":"native", "evidence":["web/api"]},
        {"id":"api.openapi", "name":"OpenAPI-driven testing", "mode":"native", "evidence":[]},
        {"id":"api.graphql", "name":"GraphQL assessment", "mode":"lab-validation", "evidence":[]},
        {"id":"api.authz", "name":"BOLA/function/property authorization testing", "mode":"lab-validation", "evidence":[]},
        {"id":"api.ratelimit", "name":"rate-limit/control testing", "mode":"native", "evidence":[]},
        {"id":"api.workflow", "name":"API workflow/state testing", "mode":"human-assisted", "evidence":[]},
    ],
    "infrastructure": [
        {"id":"infra.tls", "name":"TLS configuration observation", "mode":"native", "evidence":["evidence/tls-observation-v27.json"]},
        {"id":"infra.service", "name":"service/version enumeration", "mode":"tool-backed", "tools":["nmap"], "evidence":["ports/nmap-detailed.nmap"]},
        {"id":"infra.management", "name":"management-interface exposure assessment", "mode":"native", "evidence":[]},
        {"id":"infra.cve", "name":"CVE/exposure correlation", "mode":"tool-backed", "tools":["nuclei"], "evidence":["vulns/findings.json"]},
        {"id":"infra.segmentation", "name":"network segmentation validation", "mode":"human-assisted", "evidence":[]},
    ],
    "windows_ad": [
        {"id":"ad.users", "name":"AD users/groups/computers enumeration", "mode":"tool-backed", "tools":["nxc"], "evidence":["ad"]},
        {"id":"ad.shares", "name":"SMB/share enumeration", "mode":"tool-backed", "tools":["nxc"], "evidence":["ad"]},
        {"id":"ad.policy", "name":"password-policy assessment", "mode":"tool-backed", "tools":["nxc"], "evidence":["ad"]},
        {"id":"ad.acl", "name":"ACL/delegation/trust analysis", "mode":"native", "evidence":["evidence/ad-relationships-v32.json"]},
        {"id":"ad.kerberos", "name":"Kerberos relationship analysis", "mode":"native", "evidence":["evidence/ad-relationships-v32.json"]},
        {"id":"ad.attackpath", "name":"privilege-path analysis", "mode":"native", "evidence":[]},
    ],
    "cloud": [
        {"id":"cloud.aws", "name":"AWS read-only inventory", "mode":"tool-backed", "tools":["aws"], "evidence":["aws"]},
        {"id":"cloud.iam", "name":"cloud identity/trust analysis", "mode":"native", "evidence":[]},
        {"id":"cloud.storage", "name":"cloud storage exposure assessment", "mode":"native", "evidence":[]},
        {"id":"cloud.network", "name":"cloud network/security-group analysis", "mode":"native", "evidence":[]},
        {"id":"cloud.azure", "name":"Azure read-only assessment", "mode":"tool-backed", "tools":["az"], "evidence":["evidence/cloud-azure-live-v32.json","evidence/cloud-azure-assessment-v32.json"]},
        {"id":"cloud.gcp", "name":"GCP read-only assessment", "mode":"tool-backed", "tools":["gcloud"], "evidence":["evidence/cloud-gcp-live-v32.json","evidence/cloud-gcp-assessment-v32.json"]},
        {"id":"cloud.k8s", "name":"Kubernetes read-only assessment", "mode":"tool-backed", "tools":["kubectl"], "evidence":["evidence/cloud-kubernetes-live-v32.json","evidence/cloud-kubernetes-assessment-v32.json"]},
    ],
    "mobile_wireless": [
        {"id":"mobile.apk", "name":"Android APK static assessment", "mode":"native", "evidence":["android-analysis.json"]},
        {"id":"mobile.dynamic", "name":"Android emulator read-only dynamic inspection", "mode":"native", "evidence":[]},
        {"id":"mobile.ios", "name":"iOS application static assessment", "mode":"native", "evidence":["evidence/ios-static-v32.json"]},
        {"id":"mobile.ios.dynamic", "name":"iOS simulator/runtime dynamic inspection", "mode":"native", "evidence":["evidence/ios-dynamic-v33.json"]},
        {"id":"wireless.pcap", "name":"wireless PCAP analysis", "mode":"native", "evidence":[]},
        {"id":"wireless.radio", "name":"Wi-Fi interface/radio inventory", "mode":"native", "evidence":[]},
        {"id":"wireless.rogue", "name":"rogue-AP/segmentation analysis", "mode":"native", "evidence":[]},
        {"id":"wireless.ble", "name":"Bluetooth/BLE passive assessment", "mode":"native", "evidence":["evidence/ble-assessment-v32.json"]},
    ],
    "remote_red_team": [
        {"id":"remote.rce", "name":"controlled RCE proof", "mode":"lab-only", "evidence":["remote-assessment.json"]},
        {"id":"remote.command", "name":"controlled command-injection proof", "mode":"lab-only", "evidence":[]},
        {"id":"remote.creds", "name":"credential-exposure validation", "mode":"lab-only", "evidence":[]},
        {"id":"remote.privesc", "name":"controlled privilege-escalation proof", "mode":"lab-only", "evidence":[]},
        {"id":"remote.persistence", "name":"controlled persistence proof", "mode":"lab-only", "evidence":[]},
        {"id":"remote.lateral", "name":"controlled lateral-access proof", "mode":"lab-only", "evidence":[]},
        {"id":"remote.objective", "name":"controlled objective-access proof", "mode":"lab-only", "evidence":[]},
        {"id":"redteam.c2", "name":"C2/malware operations", "mode":"restricted-human-led", "evidence":[]},
        {"id":"redteam.evasion", "name":"evasion/stealth tradecraft", "mode":"restricted-human-led", "evidence":[]},
        {"id":"redteam.physical", "name":"physical/social-engineering operations", "mode":"human-led", "evidence":[]},
        {"id":"redteam.destructive", "name":"destructive-impact simulation", "mode":"restricted-human-led", "evidence":[]},
    ],
    "research_limits": [
        {"id":"research.novel_zero_day", "name":"novel zero-day discovery and exploit research", "mode":"gap", "evidence":[]},
    ],
    "depth_expansion": [
        {"id":"network.database_surface", "name":"database exposure analysis", "mode":"native", "evidence":["evidence/database-surface-v33.json"]},
        {"id":"network.device_config", "name":"network-device configuration review", "mode":"native", "evidence":["evidence/network-device-config-v33.json"]},
        {"id":"cloud.container_static", "name":"container image static security assessment", "mode":"native", "evidence":["evidence/container-security-v33.json"]},
        {"id":"mobile.ios.runtime", "name":"iOS simulator runtime inspection", "mode":"native", "evidence":["evidence/ios-dynamic-v33.json"]},
    ],
    "platform_depth_v34": [
        {"id":"platform.surface_normalization","name":"normalized attack-surface inventory","mode":"native","evidence":["evidence/normalized-attack-surface-v34.json"]},
        {"id":"platform.mission_planning","name":"evidence-driven bounded mission planning","mode":"native","evidence":["evidence/mission-plan-v34.json"]},
        {"id":"platform.evidence_quality","name":"evidence provenance and hashing","mode":"native","evidence":["evidence/evidence-quality-v34.json"]},
        {"id":"platform.retest_compare","name":"deterministic snapshot retest comparison","mode":"native","evidence":["evidence/retest-comparison-v34.json"]},
        {"id":"platform.report_pack","name":"evidence-backed report packaging","mode":"native","evidence":["reports/assessment-report-v34.md"]},
    ],
    "analysis_reporting": [
        {"id":"analysis.correlation", "name":"cross-engine evidence correlation", "mode":"native", "evidence":["evidence/cross-engine-correlation-v26.json"]},
        {"id":"analysis.integrity", "name":"artifact integrity inventory", "mode":"native", "evidence":["evidence/artifact-inventory-v26.json"]},
        {"id":"analysis.coverage", "name":"truthful execution coverage", "mode":"native", "evidence":["evidence/coverage-v26.json"]},
        {"id":"analysis.reporting", "name":"technical/executive reporting", "mode":"native", "evidence":["reports"]},
        {"id":"analysis.retest", "name":"retest/closure tracking", "mode":"native", "evidence":[]},
        {"id":"analysis.attribution", "name":"final threat attribution", "mode":"human-led", "evidence":[]},
    ],
}

MODE_WEIGHT = {
    "native": 1.0,
    "tool-backed": 1.0,
    "lab-validation": 0.75,
    "human-assisted": 0.55,
    "lab-only": 0.45,
    "human-led": 0.35,
    "restricted-human-led": 0.25,
    "gap": 0.0,
}


def _available_tools(inventory: list[dict[str, Any]]) -> set[str]:
    return {str(x.get("name") or x.get("tool_id")) for x in inventory if isinstance(x, dict) and (x.get("available") is True or x.get("status") == "ready")}


def _has_evidence(root: Path, rels: list[str]) -> bool:
    if not rels:
        return False
    for rel in rels:
        p = root / rel
        if p.exists() and ((p.is_file() and p.stat().st_size > 0) or p.is_dir()):
            return True
        # A directory-like evidence token may be represented by a file whose
        # name contains the directory name.
        if not p.exists() and any(x.is_file() for x in root.glob(rel + "*")):
            return True
    return False


def build(root: str | Path, *, tool_inventory=None) -> dict:
    root = Path(root)
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    inv = tool_inventory or []
    available = _available_tools(inv)
    rows = []
    for domain, items in CAPABILITY_CATALOG.items():
        for item in items:
            mode = item["mode"]
            tools = item.get("tools", [])
            evidence_ok = _has_evidence(root, item.get("evidence", []))
            missing_tools = sorted(set(tools) - available)
            if mode == "gap": status = "gap"
            elif mode in {"human-led", "restricted-human-led", "human-assisted"}:
                status = "human-required"
            elif mode == "lab-only":
                status = "lab-only"
            elif missing_tools:
                status = "implemented-but-tool-missing"
            elif evidence_ok:
                status = "executed-evidence-backed"
            else:
                status = "implemented-not-executed"
            rows.append({**item, "domain": domain, "status": status, "missing_tools": missing_tools, "evidence_present": evidence_ok})
    counts = {}
    for r in rows: counts[r["status"]] = counts.get(r["status"], 0) + 1
    executable = [r for r in rows if r["status"] in {"executed-evidence-backed", "implemented-not-executed", "implemented-but-tool-missing"}]
    score = round(sum(MODE_WEIGHT.get(r["mode"], 0) for r in rows) / max(1, len(rows)) * 100, 1)
    gaps = sorted((r for r in rows if r["status"] in {"gap", "implemented-but-tool-missing"}), key=lambda r: (r["status"] != "gap", r["domain"], r["id"]))
    data = {
        "schema_version": VERSION,
        "scope": "expert pentest and red-team capability coverage audit",
        "catalog_size": len(rows),
        "maturity_score": score,
        "status_counts": counts,
        "capabilities": rows,
        "priority_gaps": [{"id":r["id"],"domain":r["domain"],"name":r["name"],"reason":r["status"],"missing_tools":r.get("missing_tools",[])} for r in gaps],
        "interpretation": "The score measures platform coverage, not offensive effectiveness. Evidence-backed execution is distinct from implementation; human-led and restricted activities remain explicitly visible.",
        "red_team_boundary": ["No unrestricted malware/C2", "No stealth/evasion automation", "No destructive automation", "No uncontrolled propagation", "No real-data exfiltration"],
    }
    atomic_write_json(evidence / "expert-capability-audit-v27.json", data)
    return data

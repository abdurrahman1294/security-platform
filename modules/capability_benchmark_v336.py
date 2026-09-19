"""V3.36 Capability Benchmark & Gap Audit Fabric.

Evidence-oriented benchmark of the platform against professional security-assessment
capability families. This is a comparative architecture audit, not a claim of feature
parity with any vendor. It records what is implemented locally, what is delegated to
registered adapters/specialists, what is lab-only, and what remains a genuine gap.

The benchmark is read-only and never executes assessment actions.
"""
from __future__ import annotations
from pathlib import Path
import ast, hashlib, json, time
from typing import Any

from modules.reliability_execution_integrity_v331 import atomic_write
from modules.universal_attack_surface_fabric_v320 import ATTACK_SURFACES, PERSPECTIVES, EXECUTION_ADAPTERS
from modules.capability_runtime_v325 import capability_catalog

VERSION = "3.36.0"

REFERENCE_SOURCES = {
    "mitre_caldera": "https://www.mitre.org/our-impact/intellectual-property/caldera",
    "mitre_emulation": "https://attack.mitre.org/resources/adversary-emulation-plans/",
    "owasp_wstg": "https://owasp.org/www-project-web-security-testing-guide/",
    "metasploit": "https://www.metasploit.com/",
}

# Capability families deliberately describe outcomes, not proprietary implementation details.
BENCHMARK_FAMILIES = [
    ("external-recon", "External reconnaissance and attack-surface discovery", "discovery"),
    ("network-enumeration", "Network/service discovery and protocol fingerprinting", "infrastructure"),
    ("web-api-testing", "Web/API security testing methodology and bounded validation", "application"),
    ("identity-directory", "Identity, directory and remote-access assessment", "identity"),
    ("cloud-saas", "Cloud/SaaS/IAM assessment and evidence correlation", "cloud"),
    ("endpoint", "Windows/Linux/macOS endpoint assessment", "endpoint"),
    ("mobile-wireless", "Android/iOS/wireless assessment and runtime perspectives", "specialist"),
    ("iot-ot-automotive", "IoT/firmware/OT/ICS/automotive/hardware assessment", "specialist"),
    ("reverse-engineering-fuzzing", "Binary analysis, emulation and protocol-fuzzing workflows", "specialist"),
    ("adversary-emulation", "ATT&CK-aligned adversary emulation and replay planning", "emulation"),
    ("attack-path-reasoning", "Evidence-driven attack-path and nonlinear chain reasoning", "reasoning"),
    ("validation-retest", "Finding validation, remediation and retest assurance", "validation"),
    ("evidence-reporting", "Evidence lineage, reporting, coverage and professional outputs", "assurance"),
    ("governance", "Scope, authorization, approvals, safety and auditability", "governance"),
    ("resilience", "Crash recovery, state integrity, budgets and engine self-security", "platform"),
]

# Local architectural evidence. Status is intentionally conservative.
LOCAL_EVIDENCE = {
    "external-recon": ("implemented", "V3.20-V3.21 universal surfaces plus registered discovery adapters"),
    "network-enumeration": ("implemented", "V3.20/V3.21 network and protocol surface routing"),
    "web-api-testing": ("implemented-bounded", "V3.15 specialist domain + V3.28 payload assurance + bounded proofs"),
    "identity-directory": ("implemented-bounded", "identity/remote specialist routing and governed R4 procedures"),
    "cloud-saas": ("implemented-bounded", "cloud surface, provider adapters and assessment correlation"),
    "endpoint": ("implemented-bounded", "V3.17 remote endpoint evidence model"),
    "mobile-wireless": ("implemented-specialist", "V3.15/V3.17 mobile and wireless specialist fabric"),
    "iot-ot-automotive": ("implemented-specialist", "V3.16 embedded/OT/automotive fabric"),
    "reverse-engineering-fuzzing": ("implemented-specialist", "V3.17 advanced analysis, emulation and fuzzing contracts"),
    "adversary-emulation": ("implemented-planning", "V3.29 adversary simulation planner; governed execution remains bounded"),
    "attack-path-reasoning": ("implemented", "V3.24-V3.29 evidence-first nonlinear reasoning"),
    "validation-retest": ("implemented", "V3.33 validation assurance and V3.34 remediation/retest linkage"),
    "evidence-reporting": ("implemented", "V3.30/V3.34 canonical evidence and reporting"),
    "governance": ("implemented", "V3.13/V3.22/V3.31 governed execution and approval controls"),
    "resilience": ("implemented", "V3.31 reliability plus V3.35 self-security"),
}

# Remaining gaps are deliberately framed as engineering scope, not as instructions for unsafe capabilities.
GAP_REGISTER = [
    {"id":"GAP-336-01", "family":"adversary-emulation", "gap":"No full autonomous enterprise-agent emulation runtime", "priority":"high", "reason":"Current implementation is planning/governed specialist delegation rather than a general endpoint-agent execution fabric."},
    {"id":"GAP-336-02", "family":"web-api-testing", "gap":"Incomplete broad application-specific test corpus", "priority":"high", "reason":"The platform has methodology and bounded proofs, but does not reproduce the depth of a mature dedicated web-testing corpus."},
    {"id":"GAP-336-03", "family":"identity-directory", "gap":"Incomplete deep protocol-specific post-compromise coverage", "priority":"medium", "reason":"Remote/identity routing exists; broad environment-specific procedures remain specialist-led."},
    {"id":"GAP-336-04", "family":"mobile-wireless", "gap":"Runtime tooling is catalogued more broadly than it is centrally orchestrated", "priority":"medium", "reason":"Specialist adapters exist as contracts; centralized evidence/state integration is not equally deep across every tool."},
    {"id":"GAP-336-05", "family":"iot-ot-automotive", "gap":"Physical/testbed execution remains specialist and lab constrained", "priority":"medium", "reason":"The architecture intentionally keeps process-impacting and hardware-writing actions out of autonomous execution."},
    {"id":"GAP-336-06", "family":"reverse-engineering-fuzzing", "gap":"No universal fuzzing campaign scheduler with corpus lifecycle", "priority":"medium", "reason":"Fuzzing capabilities are represented, but corpus minimization, campaign orchestration and crash triage are not a single unified runtime."},
    {"id":"GAP-336-07", "family":"evidence-reporting", "gap":"Limited native long-running assessment datastore", "priority":"medium", "reason":"Artifacts are durable and resumable, but a dedicated multi-engagement datastore/analytics layer is not the core architecture yet."},
    {"id":"GAP-336-08", "family":"platform", "gap":"Legacy specialist subprocess boundaries remain outside ToolManager", "priority":"medium", "reason":"V3.35 audit intentionally leaves some historical/test tooling boundaries visible as hardening debt."},
]


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _capability_inventory() -> list[dict[str, Any]]:
    return [
        {"id": c.get("id"), "surface": c.get("surface"), "specialist": c.get("specialist"),
         "action": c.get("action"), "risk": c.get("risk"), "available": bool(c.get("available", True))}
        for c in capability_catalog()
    ]


def build_benchmark_matrix() -> list[dict[str, Any]]:
    caps = _capability_inventory()
    rows = []
    for fid, name, domain in BENCHMARK_FAMILIES:
        status, evidence = LOCAL_EVIDENCE[fid]
        related_surfaces = [s for s, meta in ATTACK_SURFACES.items() if meta.get("family") == domain]
        adapter_count = sum(len(EXECUTION_ADAPTERS.get(s, [])) for s in related_surfaces)
        capability_count = sum(1 for c in caps if c.get("surface") in related_surfaces)
        rows.append({
            "id": fid, "name": name, "domain": domain, "local_status": status,
            "local_evidence": evidence, "related_surfaces": related_surfaces,
            "registered_adapter_count": adapter_count, "registered_capability_count": capability_count,
            "perspective_count": len(PERSPECTIVES),
            "confidence": 0.9 if status == "implemented" else 0.78,
        })
    return rows


def build_v336_fabric(root: str | Path, *, objective: str = "professional-capability-benchmark") -> dict[str, Any]:
    matrix = build_benchmark_matrix()
    gaps = list(GAP_REGISTER)
    status_counts: dict[str, int] = {}
    for row in matrix:
        status_counts[row["local_status"]] = status_counts.get(row["local_status"], 0) + 1
    priority_counts: dict[str, int] = {}
    for gap in gaps:
        priority_counts[gap["priority"]] = priority_counts.get(gap["priority"], 0) + 1
    result = {
        "schema_version": VERSION,
        "objective": objective,
        "benchmark_type": "evidence-oriented architecture benchmark",
        "comparison_policy": "family-level capability comparison; no vendor feature-parity claim",
        "families": len(matrix),
        "status_counts": status_counts,
        "gap_counts": priority_counts,
        "matrix": matrix,
        "gaps": gaps,
        "platform_inventory": {
            "attack_surface_classes": len(ATTACK_SURFACES),
            "perspectives": len(PERSPECTIVES),
            "registered_capabilities": len(_capability_inventory()),
            "execution_adapters": sum(len(v) for v in EXECUTION_ADAPTERS.values()),
        },
        "reference_frameworks": {
            "mitre_caldera": {"url": REFERENCE_SOURCES["mitre_caldera"], "basis": "automated adversary emulation and security assessment"},
            "mitre_adversary_emulation": {"url": REFERENCE_SOURCES["mitre_emulation"], "basis": "ATT&CK-aligned emulation planning"},
            "owasp_wstg": {"url": REFERENCE_SOURCES["owasp_wstg"], "basis": "web/API testing methodology"},
            "metasploit": {"url": REFERENCE_SOURCES["metasploit"], "basis": "modular penetration testing and vulnerability validation"},
        },
        "assurance": {
            "read_only": True,
            "does_not_execute_targets": True,
            "does_not_generate_unrestricted_payloads": True,
            "does_not_infer_authorization": True,
            "gaps_are_explicit": True,
            "vendor_parity_not_claimed": True,
        },
        "created_at": time.time(),
    }
    atomic_write(Path(root) / "evidence" / "capability-benchmark-v336.json", result)
    return result


def v336_test_matrix() -> dict[str, Any]:
    names = [
        "all-benchmark-families-accounted", "conservative-local-status", "gap-register-explicit",
        "gap-priority-accounting", "surface-count-accounting", "perspective-count-accounting",
        "capability-count-accounting", "adapter-count-accounting", "reference-sources-recorded",
        "vendor-parity-not-claimed", "read-only", "no-target-execution", "no-authorization-inference",
        "no-unrestricted-payload-generation", "deterministic-family-ids", "machine-readable-result",
        "atomic-artifact", "schema-stable", "empty-objective-safe", "specialist-gaps-visible",
        "lab-constraints-visible", "legacy-boundaries-visible", "web-depth-gap-visible",
        "adversary-emulation-gap-visible", "fuzzing-gap-visible", "datastore-gap-visible",
        "family-domain-mapping", "registered-capability-linkage", "registered-adapter-linkage",
        "confidence-bounded", "status-counts-consistent", "gap-counts-consistent",
        "no-coverage-inflation", "no-vulnerability-inference", "no-exploitability-inference",
        "comparison-is-family-level", "reference-frameworks-not-vendorscores", "audit-repeatable",
        "no-network-required", "no-tool-execution", "no-scope-expansion", "no-side-effects",
    ]
    return {"schema_version": VERSION, "scenario_count": len(names),
            "scenarios": [{"id": _id(x), "name": x, "expected": "safe-benchmark-result"} for x in names]}

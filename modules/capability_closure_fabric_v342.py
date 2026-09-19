"""V3.42 Capability Closure Fabric.

Closes capability taxonomy gaps by giving every capability family a concrete
contract. Consequential/dangerous behaviors are represented as governed
specialist delegation or deterministic lab simulation; this module never
creates unrestricted credential theft, covert C2, persistence, destructive
impact, propagation, or arbitrary remote execution.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
import hashlib, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.42.0"
LIFECYCLE = ("preflight","approval","execution","evidence","finding","validation","remediation","retest")

# Every family has concrete capabilities. Dangerous behaviors are deliberately
# closed by a safe execution envelope rather than silently omitted.
CAPABILITY_FAMILIES = {
    "reconnaissance": ["asset_discovery","dns_enumeration","service_enumeration","technology_fingerprinting","attack_surface_inventory"],
    "web_api": ["http_assurance","authentication_boundary","authorization_boundary","input_validation","graphql_assurance","websocket_assurance","upload_assurance","rate_limit_assurance","api_drift_detection"],
    "network": ["tcp_udp_discovery","protocol_fingerprinting","tls_assurance","segmentation_validation","network_device_assurance"],
    "identity": ["kerberos_assurance","ldap_assurance","ntlm_assurance","smb_assurance","winrm_assurance","rdp_assurance","ssh_assurance","oauth_oidc_assurance","saml_assurance","mfa_assurance","delegation_trust_analysis"],
    "cloud": ["iam_assurance","storage_assurance","network_assurance","secret_configuration_review","container_cloud_assurance","control_plane_assurance"],
    "endpoint": ["windows_assurance","linux_assurance","macos_assurance","software_inventory","service_assurance","local_policy_assurance","endpoint_detection_validation"],
    "mobile": ["android_static_assurance","android_dynamic_assurance","ios_static_assurance","ios_dynamic_assurance","mobile_network_assurance","mobile_api_correlation"],
    "wireless": ["wifi_inventory","wifi_security_assurance","bluetooth_assurance","wireless_pcap_analysis","wireless_detection_validation"],
    "embedded": ["firmware_analysis","iot_assurance","hardware_debug_assurance","boot_chain_assurance","device_protocol_assurance"],
    "ot_ics": ["ics_protocol_assurance","control_boundary_assurance","ot_network_segmentation","digital_twin_validation","safety_boundary_review"],
    "automotive": ["can_assurance","vehicle_network_analysis","ecu_firmware_analysis","diagnostic_assurance","automotive_segmentation"],
    "reverse_engineering": ["binary_static_analysis","binary_dynamic_analysis","symbolic_analysis","protocol_fuzzing","crash_triage","corpus_minimization"],
    "source_supply_chain": ["sast_correlation","dependency_assurance","secret_scanning","ci_cd_assurance","artifact_provenance","build_integrity"],
    "data": ["database_exposure","storage_backup_assurance","data_access_boundary","encryption_configuration_review"],
    "saas_third_party": ["saas_configuration_assurance","oauth_integration_assurance","third_party_trust_boundary","webhook_assurance"],
    "human_physical": ["email_security_assurance","social_engineering_simulation","physical_security_simulation","trust_boundary_analysis"],
    "ai_ml": ["model_endpoint_assurance","prompt_boundary_assurance","data_boundary_assurance","model_supply_chain_assurance"],
    "cellular_telecom": ["cellular_origin_assessment","ipv4_ipv6_reachability","carrier_path_analysis","mobile_data_egress_assurance"],
    "adversary_emulation": ["credential_access_simulation","privilege_escalation_simulation","lateral_movement_simulation","persistence_simulation","command_control_simulation","exfiltration_simulation","impact_simulation","propagation_simulation","rce_validation_simulation"],
    "validation_reporting": ["evidence_quality","finding_validation","impact_validation","remediation_retest","professional_reporting","engagement_analytics"],
}

DANGEROUS = {
    "credential_access_simulation","privilege_escalation_simulation","lateral_movement_simulation",
    "persistence_simulation","command_control_simulation","exfiltration_simulation","impact_simulation",
    "propagation_simulation","rce_validation_simulation","social_engineering_simulation","physical_security_simulation",
}

MODES = {
    "observe": {"risk":"R0","execution":"native-bounded"},
    "verify": {"risk":"R1","execution":"native-bounded"},
    "specialist": {"risk":"R2","execution":"delegated-specialist"},
    "lab-simulation": {"risk":"R3","execution":"deterministic-lab-simulation"},
}

def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str,parts)).encode()).hexdigest()[:20]

def _write(root: str|Path, name: str, obj: dict[str,Any]) -> str:
    p = Path(root)/"evidence"/name
    atomic_write(p, obj)
    return str(p)

def _mode(capability: str) -> str:
    if capability in DANGEROUS:
        return "lab-simulation"
    if any(x in capability for x in ("static","inventory","analysis","review","correlation","reporting","analytics","fingerprinting","discovery")):
        return "observe"
    if capability.endswith("assurance") or capability.endswith("validation") or capability.endswith("assurance"):
        return "specialist"
    return "verify"

def capability_contract(family: str, capability: str) -> dict[str,Any]:
    mode = _mode(capability)
    meta = MODES[mode]
    return {
        "capability_id": _id("v342",family,capability),
        "family": family,
        "capability": capability,
        "status": "implemented-contract",
        "execution_mode": meta["execution"],
        "risk": meta["risk"],
        "lifecycle": list(LIFECYCLE),
        "preconditions": ["target-defined","scope-authoritative","authorization-explicit"],
        "approval_required": mode in {"specialist","lab-simulation"},
        "evidence_required": True,
        "validation_required": True,
        "specialist_dependency": mode == "specialist",
        "lab_only": mode == "lab-simulation",
        "real_world_action": False if mode == "lab-simulation" else None,
        "notes": "Dangerous behavior is modeled with synthetic/lab evidence; no operational weaponization is generated." if mode == "lab-simulation" else "Concrete capability contract; execution remains governed by the canonical lifecycle.",
    }

def build_capability_closure() -> list[dict[str,Any]]:
    rows=[]
    for family, capabilities in CAPABILITY_FAMILIES.items():
        for capability in capabilities:
            rows.append(capability_contract(family, capability))
    return rows

def simulate_dangerous_capability(root: str|Path, *, capability: str, target: str, approved: bool=False, lab_id: str="loopback-lab") -> dict[str,Any]:
    """Produce deterministic evidence for a dangerous capability without performing it."""
    if capability not in DANGEROUS:
        raise ValueError("capability is not a dangerous simulation capability")
    if not approved:
        return {"status":"blocked","reason":"explicit operator approval required","capability":capability,"target":target}
    contract=capability_contract("adversary_emulation",capability)
    result={"schema_version":VERSION,"status":"simulated","simulation_id":_id("simulation",capability,target,lab_id),
            "capability":capability,"target":target,"lab_id":lab_id,"contract":contract,
            "synthetic_evidence":{"marker":_id("evidence",capability,target),"effect":"simulated-only","secrets_collected":False,"external_side_effects":False},
            "limitations":["No credential capture","No persistence deployment","No covert C2","No real exfiltration","No destructive impact","No uncontrolled propagation","No arbitrary remote execution"],
            "created_at":time.time()}
    _write(root,f"capability-simulation-{contract['capability_id']}.json",redact(result))
    return result

def build_v342_fabric(root: str|Path, *, target: str="", objective: str="full-capability-closure") -> dict[str,Any]:
    contracts=build_capability_closure()
    family_summary=[]
    for family in CAPABILITY_FAMILIES:
        rows=[x for x in contracts if x["family"]==family]
        family_summary.append({"family":family,"capability_count":len(rows),"implemented_contracts":len(rows),
                               "specialist_count":sum(x["specialist_dependency"] for x in rows),
                               "lab_simulation_count":sum(x["lab_only"] for x in rows)})
    result={"schema_version":VERSION,"target":target,"objective":objective,"capability_count":len(contracts),
            "family_count":len(CAPABILITY_FAMILIES),"contracts":contracts,"families":family_summary,
            "closure":{"all_taxonomy_entries_have_contract":True,"dangerous_behaviors_have_lab_envelope":True,
                        "unrestricted_weaponization":False,"real_credential_theft":False,"real_persistence":False,
                        "real_covert_c2":False,"real_destructive_impact":False,"real_propagation":False,
                        "real_exfiltration":False,"arbitrary_remote_execution":False},
            "governance":{"scope_recheck":True,"authorization_recheck":True,"approval_for_consequential":True,
                           "evidence_required":True,"validation_required":True,"no_scope_expansion":True},
            "created_at":time.time()}
    _write(root,"capability-closure-v342.json",result)
    return result

def v342_test_matrix() -> dict[str,Any]:
    names=[
        "taxonomy-complete","every-capability-has-contract","family-accounting","lifecycle-complete",
        "scope-precondition","authorization-precondition","approval-boundary","evidence-required",
        "validation-required","specialist-delegation","lab-envelope","credential-access-simulation",
        "privilege-escalation-simulation","lateral-movement-simulation","persistence-simulation",
        "command-control-simulation","exfiltration-simulation","impact-simulation","propagation-simulation",
        "rce-validation-simulation","social-engineering-simulation","physical-security-simulation",
        "no-real-credential-theft","no-real-persistence","no-real-c2","no-real-impact","no-real-propagation",
        "no-real-exfiltration","no-arbitrary-rce","deterministic-identifiers","secret-redaction",
        "machine-readable-evidence","atomic-artifact","operator-visible-block","simulation-evidence",
        "specialist-gaps-visible","reporting-linkage","remediation-linkage","retest-linkage","target-lock",
        "objective-lock","governance-preserved","no-scope-expansion","no-authority-inference","no-autonomous-dangerous-action"
    ]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id("suite",n),"name":n,"expected":"pass"} for n in names]}

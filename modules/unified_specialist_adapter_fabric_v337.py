"""V3.37 Unified Specialist Adapter Fabric.

Normalizes specialist capabilities into one governed lifecycle without adding
an arbitrary-command or unrestricted-agent execution path.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.37.0"
LIFECYCLE = ("preflight", "approval", "execution", "evidence", "failure", "finding", "validation", "remediation", "retest")
RISK = {"R0":0,"R1":1,"R2":2,"R3":3,"R4":4,"R5":5}
DENIED = {"unrestricted_rce","credential_theft","persistence","covert_c2","destructive_impact","uncontrolled_propagation","real_data_exfiltration","carrier_bypass"}
SPECIALISTS = {
    "web": ["external_web","api"], "network": ["internet_services","remote_access","network_devices"],
    "identity": ["identity_directory"], "cloud": ["cloud","saas"], "endpoint": ["endpoint_windows","endpoint_linux","endpoint_macos"],
    "mobile": ["mobile_android","mobile_ios"], "wireless": ["wireless"], "embedded": ["iot","firmware","hardware_debug"],
    "ot": ["ot_ics"], "automotive": ["automotive"], "software": ["source_code_ci_cd","supply_chain","containers","virtualization"],
    "data": ["databases","storage_backup"], "human": ["email_collaboration","human_social","physical_facility"],
    "ai": ["ai_ml"], "telecom": ["cellular_telecom"], "third_party": ["third_party_integrations"],
}

def _id(*p: Any) -> str: return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root, name, obj):
    p=Path(root)/"evidence"/name; atomic_write(p,obj); return p

def normalize_adapter(capability: dict[str,Any]) -> dict[str,Any]:
    c=redact(capability if isinstance(capability,dict) else {})
    risk=str(c.get("risk","R0")).upper(); action=str(c.get("action","observe"))
    denied=action.lower() in DENIED or str(c.get("class","")).lower() in DENIED
    return {"adapter_id":str(c.get("id") or _id("adapter",c.get("specialist"),c.get("surface"),action)),
            "specialist":str(c.get("specialist","unknown")),"surface":str(c.get("surface","unknown")),
            "action":action,"risk":risk if risk in RISK else "R0","lifecycle":list(LIFECYCLE),
            "governed":not denied,"execution_mode":"delegated-only","evidence_contract":"canonical-evidence-v1",
            "denied":denied,"approval_required":risk not in {"R0"},"scope_recheck_required":True}

def build_adapter_registry(capabilities: Iterable[dict[str,Any]]|None=None) -> list[dict[str,Any]]:
    rows=[normalize_adapter(c) for c in (capabilities or []) if isinstance(c,dict)]
    return sorted(rows,key=lambda x:x["adapter_id"])

def build_enterprise_emulation_plan() -> dict[str,Any]:
    phases=["asset-and-identity-baseline","behavior-selection","operator-approval","bounded-emulation","evidence-capture","detection-assessment","cleanup-verification","report-and-retest"]
    return {"status":"planning-capability","phases":phases,"agent_runtime":False,"endpoint_agent_execution":"specialist-dependent","behavior_catalog":"ATT&CK-aligned metadata only","human_approval_required":True,"no_credential_theft":True,"no_persistence_deployment":True,"no_covert_c2":True,"no_unrestricted_execution":True}

def build_v337_fabric(root, *, capabilities=None, target="", objective="full-assessment"):
    registry=build_adapter_registry(capabilities)
    specialist_rows=[]
    for specialist,surfaces in SPECIALISTS.items():
        matched=[x for x in registry if x["surface"] in surfaces]
        specialist_rows.append({"specialist":specialist,"surfaces":surfaces,"adapter_count":len(matched),"governed_count":sum(1 for x in matched if x["governed"]),"status":"wired" if matched else "specialist-required"})
    result={"schema_version":VERSION,"target":target,"objective":objective,"adapter_registry":registry,"specialists":specialist_rows,
            "enterprise_emulation":build_enterprise_emulation_plan(),"lifecycle":list(LIFECYCLE),
            "governance":{"scope_recheck":True,"authorization_recheck":True,"single_action_approval":True,"no_scope_expansion":True,"hard_denied":sorted(DENIED)},"created_at":time.time()}
    _write(root,"unified-specialist-adapters-v337.json",result); return result

def v337_test_matrix():
    names=["canonical-lifecycle","adapter-normalization","risk-normalization","denied-actions-visible","scope-recheck","approval-recheck","evidence-contract","specialist-routing","missing-specialist-visible","emulation-planning-only","no-agent-runtime","no-credential-theft","no-persistence","no-covert-c2","no-unrestricted-execution","no-scope-expansion","secret-redaction","deterministic-adapter-id","atomic-artifact","machine-readable","registry-sorted","governance-preserved","endpoint-gap-visible","delegation-only","operator-visible-failures","retest-lifecycle"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"governed-adapter-result"} for x in names]}

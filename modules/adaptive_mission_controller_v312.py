from __future__ import annotations
"""V3.12 adaptive mission controller.

Evidence-driven controller that repeatedly selects the highest-value next
specialist analysis, ingests its result, and re-plans. Consequential execution
remains behind the existing authorization/ROE gates. This module does not
implement payloads, C2, credential theft, persistence, evasion, or arbitrary
remote execution.
"""
import hashlib, json
from pathlib import Path
from typing import Any
from .atomic_io import atomic_write_json, load_json
from .security import redact_mapping

VERSION = "3.12.0"
FORBIDDEN = {"c2","payload_generation","credential_theft","credential_capture","persistence","evasion","arbitrary_shell","destructive_actions"}

SPECIALISTS = {
    "recon": {"signals": ["asset","subdomain","service","port","dns","http"], "outputs": ["asset_inventory","service_map"]},
    "web": {"signals": ["web","http","api","endpoint","workflow","injection","auth"], "outputs": ["web_model","api_model"]},
    "identity": {"signals": ["identity","auth","session","role","acl","ad","bloodhound"], "outputs": ["identity_model","attack_path_candidates"]},
    "cloud": {"signals": ["aws","azure","gcp","iam","bucket","kubernetes","cloud"], "outputs": ["cloud_model","misconfiguration_candidates"]},
    "mobile": {"signals": ["android","ios","apk","ipa","mobsf","frida","mobile"], "outputs": ["mobile_model","runtime_candidates"]},
    "network": {"signals": ["network","smb","ldap","rdp","ssh","snmp","service"], "outputs": ["network_model","exposure_candidates"]},
    "source": {"signals": ["source","sarif","semgrep","codeql","sink","dataflow"], "outputs": ["code_findings","dataflow_candidates"]},
    "correlator": {"signals": ["finding","candidate","relationship","evidence","correlation"], "outputs": ["hypotheses","correlations"]},
    "validator": {"signals": ["hypothesis","candidate","proof","retest","validation"], "outputs": ["validated_findings"]},
    "reporter": {"signals": ["validated","finding","remediation","report"], "outputs": ["report_pack"]},
}

def _load_evidence(root: Path) -> list[dict[str, Any]]:
    out=[]; ev=root/"evidence"
    if not ev.exists(): return out
    for p in sorted(ev.glob("*.json")):
        obj=load_json(p,None,quarantine_on_error=False)
        if obj is None: continue
        safe=redact_mapping(obj)
        out.append({"artifact":p.name,"content":safe})
    return out

def _score(role: str, evidence: list[dict[str,Any]], objective: str) -> float:
    spec=SPECIALISTS[role]; blob=json.dumps(evidence,sort_keys=True,default=str).lower()
    hits=sum(blob.count(s.lower()) for s in spec["signals"])
    missing=sum(1 for o in spec["outputs"] if o not in blob)
    objective_bonus=3 if any(x in objective.lower() for x in spec["signals"]) else 0
    return hits*1.5+missing*4+objective_bonus

def build_adaptive_mission(root: str|Path, target: str, objective: str="general", max_steps:int=12, authorized:bool=False) -> dict[str,Any]:
    root=Path(root); (root/"evidence").mkdir(parents=True,exist_ok=True)
    evidence=_load_evidence(root); steps=[]; used=set()
    for i in range(max(1,min(int(max_steps),32))):
        candidates=[(r,_score(r,evidence,objective)) for r in SPECIALISTS if r not in used]
        if not candidates: break
        role,score=max(candidates,key=lambda x:x[1])
        used.add(role)
        consequential=role=="validator"
        status="ready" if (not consequential or authorized) else "approval_required"
        steps.append({"step":i+1,"specialist":role,"priority":round(score,2),"status":status,
                      "inputs_from": [x["artifact"] for x in evidence[-12:]],
                      "expected_outputs":SPECIALISTS[role]["outputs"],
                      "replan_after_completion":True,
                      "authorization_recheck":True,"scope_recheck":True})
        evidence.append({"artifact":f"planned-step-{i+1}-{role}","content":{"planned_role":role,"outputs":SPECIALISTS[role]["outputs"]}})
    data={"schema_version":VERSION,"target":target,"objective":objective,"authorized_at_plan_time":bool(authorized),
          "controller":"observe -> score -> select specialist -> execute through existing gate -> ingest evidence -> replan",
          "steps":steps,"stop_conditions":["scope change","authorization failure","kill switch","critical tool failure","evidence integrity failure"],
          "safety":{"forbidden_autonomy":sorted(FORBIDDEN),"no_scope_expansion":True,"no_secret_retention":True}}
    atomic_write_json(root/"evidence"/"adaptive-mission-v312.json",data); return data

def build_capability_fusion_matrix(root: str|Path)->dict[str,Any]:
    root=Path(root); (root/"evidence").mkdir(parents=True,exist_ok=True)
    fusion={
      "recon+web+source":"asset-to-code-to-runtime hypothesis chain",
      "identity+network+cloud":"privilege/exposure relationship graph",
      "mobile+source+runtime":"static-to-runtime mobile validation chain",
      "web+identity+browser":"authenticated workflow abuse hypothesis chain",
      "network+identity+ad_graph":"relationship-aware exposure analysis",
      "all+validator+reporter":"evidence-backed finding lifecycle with retest",
      "ATT&CK+specialists":"technique coverage mapped to observed evidence and detection validation",
    }
    data={"schema_version":VERSION,"fusion_patterns":fusion,"composition_rule":"prefer composed evidence chains over isolated scanner hits","safety":"composition never grants authority"}
    atomic_write_json(root/"evidence"/"capability-fusion-v312.json",data); return data

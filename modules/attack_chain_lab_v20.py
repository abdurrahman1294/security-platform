"""Controlled local-lab attack-chain engine (v2.1 capability expansion).

The chain is deliberately restricted to the disposable loopback lab. It can
validate realistic vulnerability classes and multiple benign persistence /
lateral-access scenarios, while keeping high-impact actions governed by ROE
and approval. No arbitrary command execution, stealth, C2, spraying,
propagation, or real-data exfiltration is implemented.
"""
from __future__ import annotations
import json, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from typing import Any
from modules.credential_intelligence_v19 import discover_web_content, load_creds, verify_local_lab
from modules.atomic_io import atomic_write_json
from modules.scope import load_scope, is_valid_target_format
from modules.lab_http import base as lab_base, request as lab_request
from modules.security import in_scope
from modules.controlled_validation_v21 import validate as validate_vulns
from modules.persistence_lab_v21 import run as validate_persistence
from modules.lateral_movement_lab_v21 import run as validate_lateral
from modules.evidence_reasoner_v21 import reason as reason_evidence
from modules.exploitation_catalog_v22 import validate as validate_exploitation

LAB_HOSTS = {"127.0.0.1", "localhost", "::1"}

def _base(url: str) -> str:
    return lab_base(url)

def _post(url: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    return lab_request(url, method="POST", data=payload or {}, headers=headers or {})

def _get(url: str, headers=None):
    return lab_request(url, method="GET", headers=headers or {})

def _json_body(result):
    try: return json.loads(result.get("body","{}"))
    except Exception: return {}

def run_lab_attack_chain(outdir: str | Path, *, initial_url="http://127.0.0.1:8080", internal_url="http://127.0.0.1:8082", authorized=False, execute=False, approval_token="", roe_permitted=False, scope_file=None):
    root=Path(outdir); root.mkdir(parents=True,exist_ok=True); evidence=root/"evidence"; evidence.mkdir(parents=True,exist_ok=True); stages=[]
    def stage(name,status,detail=None):
        item={"stage":name,"status":status,"ts":time.time()}; item.update(detail or {}); stages.append(item)
        atomic_write_json(evidence/"attack-chain-state.json", {"schema_version":"22.0","stages":stages})
    def finish(status, reason=""):
        result={"schema_version":"22.0","status":status,"stages":stages,"lab_only":True,"fake_data_only":True}
        if reason: result["reason"]=reason
        atomic_write_json(evidence/"attack-chain-final.json", result)
        return result
    if not authorized:
        stage("authorization","DENIED"); return finish("blocked", "explicit authorization required")
    if not execute:
        stage("authorization","READY"); stage("execution","DRY_RUN"); return finish("dry_run", "rerun with --execute and approved R4 token")
    if not approval_token or not roe_permitted:
        stage("authorization","DENIED",{"reason":"R4 approval token and ROE permission required"}); return finish("blocked", "R4 approval/ROE required")
    initial=_base(initial_url); internal=_base(internal_url)
    if not scope_file or not Path(scope_file).is_file():
        stage("scope","DENIED",{"reason":"authoritative scope is required"}); return finish("blocked", "authoritative scope is required")
    allowed=load_scope(str(scope_file))
    if not allowed: stage("scope","DENIED",{"reason":"scope is empty"}); return finish("blocked", "scope is empty")
    def scoped(url):
        p=urllib.parse.urlsplit(url); port=p.port or (443 if p.scheme=="https" else 80); return f"{p.hostname}:{port}"
    initial_scope,internal_scope=scoped(initial),scoped(internal)
    if not is_valid_target_format(initial_scope) or not in_scope(initial_scope,allowed): stage("scope","DENIED",{"target":initial_scope}); return finish("blocked", "initial target out of scope")
    if not is_valid_target_format(internal_scope) or not in_scope(internal_scope,allowed): stage("scope","DENIED",{"target":internal_scope}); return finish("blocked", "internal target out of scope")
    if initial==internal: stage("target_binding","DENIED"); return finish("blocked", "targets must be distinct")
    stage("scope","CONFIRMED",{"initial":initial_scope,"internal":internal_scope}); stage("authorization","CONFIRMED")

    vuln=validate_vulns(root,initial)
    stage("vulnerability_validation","CONFIRMED" if vuln.get("confirmed",0) else "NOT_CONFIRMED",{"confirmed":vuln.get("confirmed",0)})
    exploit=validate_exploitation(root,initial)
    stage("controlled_exploitation_catalog","CONFIRMED" if exploit.get("confirmed",0) else "NOT_CONFIRMED",{"confirmed":exploit.get("confirmed",0),"catalog_size":exploit.get("catalog_size",0)})
    reasoning=reason_evidence(root)
    stage("evidence_reasoning","COMPLETED",{"decisions":len(reasoning.get("decisions",[]))})

    discovery=discover_web_content(root,initial)
    stage("credential","DISCOVERED" if discovery.get("count",0) else "NOT_FOUND",{"count":discovery.get("count",0)})
    if not discovery.get("count"): return finish("incomplete", "required stage did not complete")
    creds=load_creds(str(root)); selected=next((c for c in creds if c.get("username")=="labuser"),None)
    if not selected: stage("credential","NO_LAB_LATERAL_CREDENTIAL"); return finish("incomplete", "required stage did not complete")
    verify=verify_local_lab(root,initial); valid=any(x.get("credential_id")==selected.get("credential_id") and x.get("verification_status")=="valid" for x in verify.get("results",[]))
    stage("credential_verification","VERIFIED" if valid else "UNVERIFIED",{"credential_id":selected.get("credential_id"),"username":selected.get("username")})
    if not valid: return finish("incomplete", "required stage did not complete")

    r=_post(initial+"/lab/privilege-proof",headers={"X-Lab-Proof":"PRIVESC-LAB-OK"}); b=_json_body(r)
    stage("privilege_escalation","CONFIRMED" if b.get("status")=="confirmed" else "FAILED",{"proof":b.get("proof","none")})
    if b.get("status")!="confirmed": return finish("incomplete", "required stage did not complete")

    persistence=validate_persistence(root,initial); stage("persistence","CONFIRMED" if persistence.get("confirmed",0)==len(persistence.get("results",[])) else "PARTIAL",{"confirmed":persistence.get("confirmed",0),"mechanisms":len(persistence.get("results",[]))})
    if persistence.get("confirmed",0)==0: return finish("incomplete", "required stage did not complete")

    stage("lateral_path","IDENTIFIED",{"target":internal,"methods":["http_basic","lab_token","credential_auth"]})
    lateral=validate_lateral(root,initial,internal,selected.get("username",""),selected.get("secret",""))
    stage("lateral_access","VERIFIED" if lateral.get("confirmed",0)>0 else "FAILED",{"confirmed":lateral.get("confirmed",0)})
    if lateral.get("confirmed",0)==0: return finish("incomplete", "required stage did not complete")

    r=_get(internal+"/lab/objective",headers={"X-Lab-Objective":"OBJECTIVE-LAB-OK"}); b=_json_body(r)
    stage("objective","REACHED" if b.get("status")=="reached" else "FAILED",{"objective":b.get("objective","")})
    result={"schema_version":"22.0","status":"completed" if stages[-1]["status"]=="REACHED" else "incomplete","stages":stages,"lab_only":True,"fake_data_only":True,"validation":vuln,"exploitation_catalog":exploit,"reasoning":reasoning,"persistence":persistence,"lateral":lateral}
    atomic_write_json(evidence/"attack-chain-final.json",result); return result

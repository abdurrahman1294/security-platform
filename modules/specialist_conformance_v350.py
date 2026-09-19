"""V3.50 specialist conformance and regression matrix.

Audits whether every validation-range domain maps to a specialist, has
capability contracts, and has an observable tool/readiness state. It does not
execute external tools or create a generic command runner.
"""
from __future__ import annotations
from pathlib import Path
import hashlib, json, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact
VERSION = "3.50.0"
DOMAIN_SPECIALIST = {
    "web-api":"web","network":"network","identity":"identity","cloud":"cloud","endpoint":"endpoint",
    "mobile":"mobile","wireless":"wireless","firmware-iot":"embedded","ot-ics":"ot","automotive":"automotive",
    "containers":"software","source-supply-chain":"software","reverse-engineering":"software","data":"data","ai-ml":"ai","telecom":"telecom",
}

def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]

def _write(root, name, obj):
    p=Path(root)/"evidence"/name; atomic_write(p, redact(obj)); return p

def build_conformance(root: str|Path, *, repo_root: str|Path|None=None) -> dict:
    root=Path(root); root.mkdir(parents=True, exist_ok=True)
    from modules.unified_specialist_adapter_fabric_v337 import SPECIALISTS
    from modules.capability_closure_fabric_v342 import CAPABILITY_FAMILIES
    try:
        from security_platform.core.tools import inventory
        tools=[x.__dict__ for x in inventory()]
    except Exception as exc:
        tools=[]
        inventory_error=type(exc).__name__
    else: inventory_error=""
    capability_families=set(CAPABILITY_FAMILIES)
    DOMAIN_FAMILY={"web-api":"web_api","firmware-iot":"embedded","ot-ics":"ot_ics","containers":"cloud","source-supply-chain":"source_supply_chain","reverse-engineering":"reverse_engineering","ai-ml":"ai_ml","telecom":"cellular_telecom"}
    rows=[]
    for domain,specialist in DOMAIN_SPECIALIST.items():
        specialist_wired=specialist in SPECIALISTS
        family_present=DOMAIN_FAMILY.get(domain, domain) in capability_families
        rows.append({"domain":domain,"specialist":specialist,"specialist_registered":specialist_wired,"capability_family_present":family_present,"tool_inventory_count":len(tools),"status":"conformant" if specialist_wired and family_present else "gap"})
    gaps=[r for r in rows if r["status"]!="conformant"]
    result={"schema_version":VERSION,"status":"PASS" if not gaps else "FAIL","domain_count":len(rows),"conformant_domains":len(rows)-len(gaps),"gaps":gaps,"matrix":rows,"tool_readiness":{"tool_count":len(tools),"ready":sum(x.get("status")=="ready" for x in tools),"unavailable_or_rejected":sum(x.get("status")=="unavailable-or-rejected" for x in tools),"identity_failed":sum(x.get("status")=="identity-failed" for x in tools),"errors":sum(x.get("status")=="error" for x in tools),"inventory_error":inventory_error},"safety":{"inventory_only":True,"no_external_execution":True,"no_generic_command_path":True},"created_at":time.time()}
    _write(root,"specialist-conformance-v350.json",result); return result

def v350_test_matrix():
    names=["domain-matrix","specialist-registration","capability-family","tool-readiness","gap-reporting","pass-fail-gate","inventory-only","no-generic-command-path","machine-readable","atomic-artifact","secret-redaction","deterministic-ids","all-range-domains","regression-compatible","missing-specialist-visible","missing-family-visible"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id("v350",n),"name":n,"expected":"pass"} for n in names]}

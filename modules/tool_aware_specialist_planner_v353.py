"""V3.53 tool-aware specialist planning.

Produces a bounded plan from attack-surface/domain requirements to registered
assessment tools and safe local fallbacks. It never executes tools and never
selects unrestricted command paths.
"""
from __future__ import annotations
from pathlib import Path
import hashlib, json, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact
from modules.tool_manager_v40 import TOOLS

VERSION="3.53.0"
DOMAIN_TOOLS={
 "web-api":["httpx","katana","nuclei"], "network":["nmap","naabu"], "identity":["nxc"],
 "cloud":["aws","az","gcloud"], "containers":["kubectl"], "source-supply-chain":[],
 "endpoint":["nmap"], "mobile":[], "wireless":[], "firmware-iot":[], "ot-ics":[],
 "automotive":[], "reverse-engineering":[], "data":[], "ai-ml":[], "telecom":[]
}

def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]

def build_plan(root: str|Path, domains=None, *, execute=False) -> dict:
    root=Path(root); root.mkdir(parents=True,exist_ok=True)
    requested=list(domains or DOMAIN_TOOLS)
    rows=[]
    for domain in requested:
        tools=DOMAIN_TOOLS.get(domain,[])
        registered=[t for t in tools if t in TOOLS]
        rows.append({"domain":domain,"registered_tools":registered,"unavailable_tools":[t for t in tools if t not in TOOLS],"safe_fallback":"framework-local specialist contract" if not registered else "none","execution": "disabled" if not execute else "requires separate governed executor"})
    result={"schema_version":VERSION,"status":"PASS","domains":len(rows),"plan":rows,"policy":{"planning_only":True,"no_generic_command_path":True,"no_unrestricted_execution":True,"external_targets_not_enabled":True},"created_at":time.time()}
    atomic_write(root/"evidence/tool-aware-specialist-plan-v353.json",redact(result)); return result

def v353_test_matrix():
    names=["domain-routing","registered-tools","unavailable-tools","safe-fallback","planning-only","no-generic-command","no-unrestricted-execution","all-domain-rows","deterministic-ids","machine-readable","atomic-artifact","redaction","unknown-domain-safe","empty-domain-safe","tool-catalog-bound","execution-boundary","policy-visible","limitations-visible"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id("v353-test",n),"name":n,"expected":"pass"} for n in names]}

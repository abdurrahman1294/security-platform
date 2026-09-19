"""V3.6 adaptive next-step planner.

Ranks evidence gaps rather than inventing actions. Suggestions are bounded,
non-destructive and require the normal engagement gates before execution.
"""
from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json

def _load(p, default):
    try: return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError): return default

def build(root: str|Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    suggestions=[]
    fabric=_load(ev/"intelligence-fabric-v36.json",{})
    service=_load(ev/"service-protocol-intelligence-v35.json",{})
    roles=_load(ev/"auth-role-analysis-v35.json",{})
    if fabric.get("observation_count",0)==0:
        suggestions.append({"priority":100,"gap":"asset-evidence","next_step":"Collect or import authorized asset/service evidence","reason":"No normalized observations are available","requires":"scope-and-tool-gates"})
    if service.get("service_count",0)>0:
        for row in service.get("services",[]):
            flags=row.get("flags") or []
            if flags:
                suggestions.append({"priority":90,"gap":"service-review","asset":row.get("asset"),"port":row.get("port"),"next_step":"Review configuration and exposure evidence for the observed service","reason":"Service has review flags","requires":"operator-review"})
    if roles.get("finding_count",0):
        suggestions.append({"priority":95,"gap":"authorization","next_step":"Independently reproduce the recorded authorization mismatch with approved role fixtures","reason":"Role-result analysis contains a mismatch","requires":"explicit-authorization-and-test-fixtures"})
    for rel in fabric.get("cross_domain_relationships",[]):
        suggestions.append({"priority":80,"gap":"cross-domain-validation","asset":rel.get("asset"),"next_step":"Validate the relationship endpoints and evidence provenance","reason":"Shared asset links multiple security domains","requires":"scope-and-human-review"})
    suggestions.sort(key=lambda x:(-x["priority"],x.get("asset","") or ""))
    out={"schema_version":"3.6","status":"completed","suggestion_count":len(suggestions),"suggestions":suggestions[:200],"principle":"Suggestions never grant authority and never execute target actions."}
    atomic_write_json(ev/"adaptive-next-steps-v36.json",out)
    return out

#!/usr/bin/env python3
"""V59 adaptive API testing planner; planning only, never executes tests."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime,timezone

def build(root: str|Path):
    root=Path(root); src=root/"evidence"/"api-surface-intelligence-v58.json"
    if not src.exists(): raise FileNotFoundError("V58 API surface intelligence not found")
    data=json.loads(src.read_text(encoding="utf-8")); decisions=[]
    for r in data.get("endpoints",[]):
        ep=r["endpoint"]
        if r.get("object_reference_candidates"):
            decisions.append({"decision_id":f"API59-{len(decisions)+1:04d}","priority":"high","endpoint":ep,"action":"review-object-level-authorization","reason":"Object-reference parameter candidate detected","requires_operator_approval":True,"destructive":False})
        if any(m in r.get("methods",[]) for m in ("POST","PUT","PATCH","DELETE")):
            decisions.append({"decision_id":f"API59-{len(decisions)+1:04d}","priority":"high","endpoint":ep,"action":"review-method-and-function-authorization","reason":"State-capable method candidate detected","requires_operator_approval":True,"destructive":False})
        if r.get("query_parameters"):
            decisions.append({"decision_id":f"API59-{len(decisions)+1:04d}","priority":"medium","endpoint":ep,"action":"review-input-and-field-authorization","reason":"Input parameter candidates detected","requires_operator_approval":True,"destructive":False})
    if not decisions:
        decisions.append({"decision_id":"API59-0001","priority":"medium","endpoint":"application-wide","action":"expand-api-discovery","reason":"No API candidates were identified; confirm discovery coverage","requires_operator_approval":True,"destructive":False})
    out={"schema_version":"59.0","generated":datetime.now(timezone.utc).isoformat(),"decision_count":len(decisions),"decisions":decisions,"planning_only":True,"human_control_required":True,"exploitation_authorized":False}
    ep=root/"evidence"/"api-decisions-v59.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"api-decisions-v59.md"; rp.parent.mkdir(parents=True,exist_ok=True); rp.write_text("# Adaptive API Decisions (V59)\n\n> Operator decision support only. No API test is executed by this module.\n\n"+"\n".join(f"- **{d['priority']}** `{d['action']}` → `{d['endpoint']}` — {d['reason']}" for d in decisions)+"\n",encoding="utf-8")
    return ep,rp

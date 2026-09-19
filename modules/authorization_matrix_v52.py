#!/usr/bin/env python3
"""V52 authorization test matrix. Planning only; no access-control bypass execution."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

ROLES=("anonymous","authenticated","resource-owner","privileged")
CHECKS=(
    ("anonymous","authenticated","authentication-boundary"),
    ("authenticated","resource-owner","horizontal-access-control"),
    ("resource-owner","authenticated","object-ownership-boundary"),
    ("authenticated","privileged","vertical-access-control"),
    ("privileged","authenticated","least-privilege-review"),
)

def build(root: str|Path):
    root=Path(root); src=root/"evidence"/"auth-intelligence-v51.json"
    if not src.exists(): raise FileNotFoundError("V51 auth intelligence not found; run --auth-intelligence first")
    data=json.loads(src.read_text(encoding="utf-8")); rows=[]
    for s in data.get("surfaces",[]):
        ep=s["endpoint"]
        for src_role,dst_role,check in CHECKS:
            rows.append({"test_id":f"W52-{len(rows)+1:04d}","endpoint":ep,"check":check,"source_role":src_role,"comparison_role":dst_role,
                         "priority":"high" if check in {"horizontal-access-control","vertical-access-control"} else "medium",
                         "status":"planned","operator_approval_required":True,"destructive":False,
                         "required_evidence":["sanitized request metadata","response comparison","operator role mapping"]})
    # Ensure a useful baseline even when V51 found no auth candidates.
    if not rows:
        rows.append({"test_id":"W52-0001","endpoint":"application-wide","check":"authorization-surface-mapping","source_role":"anonymous","comparison_role":"authenticated","priority":"medium","status":"planned","operator_approval_required":True,"destructive":False,"required_evidence":["documented role model"]})
    out={"schema_version":"52.0","generated":datetime.now(timezone.utc).isoformat(),"planning_only":True,"human_control_required":True,"test_count":len(rows),"tests":rows}
    ep=root/"evidence"/"authorization-matrix-v52.json"; ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"authorization-matrix-v52.md"; rp.write_text("# Authorization Test Matrix (V52)\n\n> Planning only. No test bypasses access controls or changes application state.\n\n"+"\n".join(f"- **{x['priority']}** `{x['check']}` — `{x['source_role']}` vs `{x['comparison_role']}` → `{x['endpoint']}`" for x in rows)+"\n",encoding="utf-8")
    return ep,rp

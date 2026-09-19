#!/usr/bin/env python3
"""V48: deterministic web/API test matrix from V47 candidates. Planning only."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

TESTS = {
    "API authorization": ["authorization-boundary", "object-access-control"],
    "Object-reference review": ["horizontal-access-control", "vertical-access-control"],
    "Input validation": ["reflection-observation", "type-validation", "redirect-handling"],
    "Authentication/session": ["session-boundary", "cookie-security", "failure-handling"],
    "Authentication mapping": ["auth-flow-mapping"],
    "Business logic": ["workflow-state", "step-order", "limit-enforcement"],
    "Security configuration": ["security-headers", "cors-observation", "tls-observation", "cookie-flags"],
    "API discovery": ["route-inventory", "method-inventory", "schema-exposure"],
}

def build(root: str | Path):
    root=Path(root); src=root/"evidence"/"web-assessment-plan-v47.json"
    if not src.exists(): raise FileNotFoundError("V47 plan not found; run --web-assessment-plan first")
    data=json.loads(src.read_text(encoding="utf-8")); rows=[]
    for task in data.get("tasks",[]):
        for check in TESTS.get(task.get("category"), ["operator-review"]):
            rows.append({"test_case":f"W48-{len(rows)+1:04d}","category":task.get("category"),"check":check,
                         "target":task.get("target"),"priority":task.get("priority","medium"),"status":"planned",
                         "operator_approval_required":True,"destructive":False})
    out={"schema_version":"48.0","generated":datetime.now(timezone.utc).isoformat(),"planning_only":True,"test_count":len(rows),"tests":rows}
    ep=root/"evidence"/"web-test-matrix-v48.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"web-test-matrix-v48.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    rp.write_text("# Web/API Test Matrix (V48)\n\n> Planning only. Tests are non-destructive and require operator approval.\n\n"+"\n".join(f"- **{x['priority']}** `{x['test_case']}` — {x['category']} / {x['check']} → `{x['target']}`" for x in rows)+"\n",encoding="utf-8")
    return ep,rp

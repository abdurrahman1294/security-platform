#!/usr/bin/env python3
"""V47 web/API assessment planner.

Produces a prioritized, operator-facing test plan from the structured endpoint
model. It does not execute tests.
"""
from __future__ import annotations
import json, uuid
from pathlib import Path
from datetime import datetime, timezone

def _task(category, target, rationale, priority, evidence):
    return {"test_id":f"W47-{uuid.uuid4().hex[:8]}","category":category,"target":target,"priority":priority,
            "status":"planned","rationale":rationale,"expected_evidence":evidence,"operator_approval_required":True}

def build(root: str|Path):
    root=Path(root); (root/"reports").mkdir(parents=True,exist_ok=True); src=root/"evidence"/"web-endpoints-v46.json"
    if not src.exists(): raise FileNotFoundError("V46 endpoint model not found; run --web-endpoints first")
    data=json.loads(src.read_text(encoding="utf-8"))
    tasks=[]
    for e in data.get("endpoints",[]):
        ep=e["endpoint"]
        if e.get("type")=="api":
            tasks.append(_task("API authorization",ep,"Check object and function authorization with approved test identities.","high","request/response comparison and access-control evidence"))
        if e.get("parameters"):
            tasks.append(_task("Input validation",ep,"Review parameter handling for injection, reflection, type confusion and unsafe redirects.","medium","bounded request/response evidence"))
        if e.get("risk_signals"):
            tasks.append(_task("Object-reference review",ep,"Review sensitive/object identifiers for horizontal and vertical authorization issues.","high","two-role comparison or documented negative test"))
        if e.get("auth_likelihood")!="unknown":
            tasks.append(_task("Authentication/session",ep,"Review authentication boundaries, session handling and failure behavior.","high","sanitized authentication observations"))
    for ep in data.get("authentication_map",[]):
        tasks.append(_task("Authentication mapping",ep,"Map login/token/session flow before deeper authorization testing.","high","flow diagram or sanitized request metadata"))
    for ep in data.get("business_logic_candidates",[]):
        tasks.append(_task("Business logic",ep,"Manually test workflow integrity, step skipping, limits and state transitions.","high","workflow evidence and business-impact notes"))
    # Always include low-impact baseline checks once per engagement.
    tasks.extend([
        _task("Security configuration", "application-wide", "Review HTTPS, security headers, CORS, cookie flags and exposed metadata.", "medium", "sanitized headers/config observations"),
        _task("API discovery", "application-wide", "Review documented and discovered API routes, methods and schema exposure.", "medium", "endpoint inventory and documentation references"),
    ])
    seen=set(); unique=[]
    for t in tasks:
        key=(t["category"],t["target"])
        if key not in seen: seen.add(key); unique.append(t)
    payload={"schema_version":"47.0","generated":datetime.now(timezone.utc).isoformat(),"human_control_required":True,
             "mode":"planning-only","task_count":len(unique),"tasks":unique}
    ep=root/"evidence"/"web-assessment-plan-v47.json"; ep.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# Deep Web/API Assessment Plan (V47)","","> Planning only. Every test requires operator review/approval and must remain within the engagement scope.","", "| Priority | Category | Target | Status |", "|---|---|---|---|"]
    rank={"high":0,"medium":1,"low":2}
    for t in sorted(unique,key=lambda x:(rank.get(x["priority"],9),x["category"],x["target"])):
        lines.append(f"| **{t['priority']}** | {t['category']} | `{t['target']}` | `{t['status']}` |")
    rp=root/"reports"/"web-assessment-plan-v47.md"; rp.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return ep,rp

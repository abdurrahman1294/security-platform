#!/usr/bin/env python3
"""V56 identity-state transition planner and decision support."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

def build(root: str|Path):
    root=Path(root); s=root/"evidence"/"session-intelligence-v54.json"; o=root/"evidence"/"session-observations-v55.json"
    if not s.exists(): raise FileNotFoundError("V54 session intelligence not found")
    sd=json.loads(s.read_text(encoding="utf-8")); od=json.loads(o.read_text(encoding="utf-8")) if o.exists() else {"results":[]}
    obs={x.get("url"):x for x in od.get("results",[])}
    decisions=[]
    for c in sd.get("session_checks",[]):
        r=obs.get(c["endpoint"])
        action="operator-confirm-expected-state"
        reason="Document the expected identity/session transition and compare it using explicitly authorized test identities."
        if c["check"]=="logout-invalidates-session": action="manually-confirm-logout-invalidation"
        elif c["check"]=="session-rotation": action="manually-confirm-session-rotation"
        elif c["check"]=="session-timeout": action="manually-confirm-timeout-policy"
        elif c["check"]=="re-authentication-boundary": action="manually-map-sensitive-action-boundary"
        elif c["check"]=="role-transition": action="manually-confirm-role-transition"
        if r and r.get("status")=="observed": reason += " A bounded public response exists; it is not evidence of a session flaw by itself."
        decisions.append({"check_id":c["check_id"],"endpoint":c["endpoint"],"check":c["check"],"priority":c["priority"],"next_action":action,"reason":reason,
                          "human_control_required":True,"exploitation_authorized":False,"credentials_collected":False})
    decisions.sort(key=lambda x:{"high":0,"medium":1,"low":2}.get(x["priority"],9))
    out={"schema_version":"56.0","generated":datetime.now(timezone.utc).isoformat(),"decision_only":True,"human_control_required":True,
         "exploitation_authorized":False,"credentials_collected":False,"secret_values_collected":False,"decisions":decisions}
    ep=root/"evidence"/"identity-transitions-v56.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"identity-transitions-v56.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    rp.write_text("# Identity & Session Transition Decisions (V56)\n\n> Decision support only. No credentials are collected and no decision authorizes exploitation.\n\n"+"\n".join(f"- **{d['priority']}** `{d['check']}` → **{d['next_action']}** — {d['reason']}" for d in decisions)+"\n",encoding="utf-8")
    return ep,rp

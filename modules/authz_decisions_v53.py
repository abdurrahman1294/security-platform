#!/usr/bin/env python3
"""V53 authentication/authorization decision support from V51/V52 and safe observations."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

def build(root: str|Path):
    root=Path(root); a=root/"evidence"/"auth-intelligence-v51.json"; m=root/"evidence"/"authorization-matrix-v52.json"
    if not a.exists(): raise FileNotFoundError("V51 auth intelligence not found")
    if not m.exists(): raise FileNotFoundError("V52 authorization matrix not found")
    ad=json.loads(a.read_text(encoding="utf-8")); md=json.loads(m.read_text(encoding="utf-8"))
    obs={}
    p=root/"evidence"/"web-probe-v49.json"
    if p.exists():
        try:
            for r in json.loads(p.read_text(encoding="utf-8")).get("results",[]): obs[r.get("url")]=r
        except json.JSONDecodeError: pass
    decisions=[]
    for t in md.get("tests",[]):
        r=obs.get(t.get("endpoint"));
        if t["check"] in {"horizontal-access-control","vertical-access-control"}:
            action="confirm-role-pair-and-manually-validate"
            reason="Authorization boundary candidate requires two explicitly authorized identities and a documented expected-access result."
        elif t["check"]=="authentication-boundary":
            action="map-authentication-flow"
            reason="Confirm where anonymous access ends and authenticated access begins without collecting credentials."
        else:
            action="review-least-privilege"
            reason="Confirm intended role permissions before any comparison test."
        if r and r.get("status")=="observed": reason += " A bounded response exists, but it is not proof of an authorization flaw."
        decisions.append({"test_id":t["test_id"],"endpoint":t["endpoint"],"check":t["check"],"priority":t["priority"],"next_action":action,"reason":reason,"human_control_required":True})
    decisions.sort(key=lambda x:{"high":0,"medium":1,"low":2}.get(x["priority"],9))
    out={"schema_version":"53.0","generated":datetime.now(timezone.utc).isoformat(),"decision_only":True,"human_control_required":True,"secret_values_collected":False,"decisions":decisions}
    ep=root/"evidence"/"authz-decisions-v53.json"; ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"authz-decisions-v53.md"; rp.write_text("# Authentication & Authorization Decisions (V53)\n\n> Decision support only. No decision authorizes bypass, mutation, credential use, or exploitation.\n\n"+"\n".join(f"- **{x['priority']}** `{x['check']}` → **{x['next_action']}** — {x['reason']}" for x in decisions)+"\n",encoding="utf-8")
    return ep,rp

#!/usr/bin/env python3
"""V54 session lifecycle intelligence. Models session controls without collecting secrets."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

SESSION_TERMS=("login","signin","logout","signout","session","token","refresh","authorize","callback","account","password","reset")
COOKIE_HINTS=("session","sid","auth","token","jwt","access","refresh")

def _surface_kind(endpoint: str) -> str:
    path=(urlparse(endpoint).path or "").lower()
    if any(x in path for x in ("logout","signout","sign-out")): return "logout"
    if any(x in path for x in ("refresh",)): return "refresh"
    if "session" in path: return "session"
    if any(x in path for x in ("login","signin","sign-in")): return "login"
    if any(x in path for x in ("authorize","oauth","sso","callback")): return "federation"
    return "auth-state"

def build(root: str|Path):
    root=Path(root); src=root/"evidence"/"auth-intelligence-v51.json"
    if not src.exists(): raise FileNotFoundError("V51 auth intelligence not found; run --auth-intelligence first")
    data=json.loads(src.read_text(encoding="utf-8")); surfaces=[]
    seen=set()
    for item in data.get("surfaces",[]):
        ep=item.get("endpoint","")
        if not ep.startswith(("http://","https://")) or ep in seen: continue
        seen.add(ep); kind=_surface_kind(ep)
        surfaces.append({"endpoint":ep,"surface_type":kind,"state_transition":{
            "pre_state":"unknown","post_state":"unknown","operator_confirmation_required":True},
            "secret_handling":"not-collected","operator_approval_required":True})
    checks=[]
    templates=[
        ("login-to-authenticated","Confirm successful login creates the intended authenticated state."),
        ("logout-invalidates-session","Confirm logout invalidates the intended session state."),
        ("session-rotation","Confirm session identifiers rotate across the documented authentication boundary."),
        ("session-timeout","Confirm idle/absolute timeout behavior matches the engagement requirement."),
        ("re-authentication-boundary","Confirm sensitive actions require re-authentication where intended."),
        ("role-transition","Confirm role changes update effective authorization state."),
    ]
    for s in surfaces:
        for name,reason in templates:
            checks.append({"check_id":f"V54-{len(checks)+1:04d}","endpoint":s["endpoint"],"check":name,"reason":reason,
                           "priority":"high" if name in {"logout-invalidates-session","session-rotation","role-transition"} else "medium",
                           "status":"planned","destructive":False,"credentials_collected":False,"operator_approval_required":True})
    out={"schema_version":"54.0","generated":datetime.now(timezone.utc).isoformat(),"secret_values_collected":False,
         "credentials_collected":False,"human_control_required":True,"surface_count":len(surfaces),"surfaces":surfaces,
         "session_checks":checks,"lifecycle_states":["anonymous","authenticating","authenticated","session-bound","privileged","logged-out","expired"],
         "notes":["Session lifecycle is modeled only; no credential, cookie, token, or session value is collected or persisted."]}
    ep=root/"evidence"/"session-intelligence-v54.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"session-intelligence-v54.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    body=["# Session & Identity Intelligence (V54)",""," > Candidate lifecycle mapping only. Secrets and credentials are never collected.","","## Surfaces"]
    body += [f"- `{s['surface_type']}` — `{s['endpoint']}`" for s in surfaces]
    body += ["","## Planned checks"] + [f"- **{c['priority']}** `{c['check']}` → `{c['endpoint']}`" for c in checks]
    rp.write_text("\n".join(body)+"\n",encoding="utf-8")
    return ep,rp

#!/usr/bin/env python3
"""V51 authentication intelligence: model auth boundaries without handling secrets."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

AUTH_TERMS=("login","signin","sign-in","logout","signout","sign-out","oauth","authorize","token","session","sso","callback","register","signup","password","reset")

def _kind(ep: str) -> str:
    p=urlparse(ep); path=(p.path or "").lower()
    if any(x in path for x in ("logout","signout","sign-out")): return "logout"
    if any(x in path for x in ("login","signin","sign-in")): return "login"
    if any(x in path for x in ("oauth","authorize","callback","sso")): return "federation"
    if "token" in path: return "token"
    if "session" in path: return "session"
    if any(x in path for x in ("register","signup","password","reset")): return "account"
    return "candidate"

def build(root: str|Path):
    root=Path(root); src=root/"evidence"/"web-endpoints-v46.json"
    if not src.exists(): raise FileNotFoundError("V46 endpoint model not found; run --web-endpoints first")
    data=json.loads(src.read_text(encoding="utf-8")); endpoints=[]
    for e in data.get("endpoints",[]):
        ep=e.get("endpoint","")
        if not ep.startswith(("http://","https://")): continue
        kind=_kind(ep)
        likelihood=e.get("auth_likelihood","unknown")
        if kind!="candidate" or likelihood!="unknown":
            endpoints.append({"endpoint":ep,"auth_surface":kind,"auth_likelihood":likelihood,"method_candidates":["GET"],"secret_handling":"not-collected","operator_review_required":True})
    # Preserve explicit authentication_map entries from V46 even if they were not endpoint records.
    for ep in data.get("authentication_map",[]):
        if ep.startswith(("http://","https://")) and not any(x["endpoint"]==ep for x in endpoints):
            endpoints.append({"endpoint":ep,"auth_surface":_kind(ep),"auth_likelihood":"high","method_candidates":["GET"],"secret_handling":"not-collected","operator_review_required":True})
    types=sorted({x["auth_surface"] for x in endpoints})
    boundaries=[]
    if endpoints:
        boundaries=[{"boundary_id":"AUTH-ANON","from":"anonymous","to":"authenticated","evidence":"candidate authentication surfaces","confidence":"medium"},
                    {"boundary_id":"AUTH-SESSION","from":"authenticated","to":"session-bound","evidence":"session/token candidates","confidence":"low-to-medium"},
                    {"boundary_id":"AUTH-PRIV","from":"authenticated","to":"privileged","evidence":"role boundary requires operator mapping","confidence":"hypothesis"}]
    out={"schema_version":"51.0","generated":datetime.now(timezone.utc).isoformat(),"secret_values_collected":False,"human_control_required":True,
         "auth_surface_count":len(endpoints),"auth_surface_types":types,"surfaces":endpoints,"trust_boundaries":boundaries,
         "roles_to_confirm":["anonymous","authenticated","resource-owner","privileged"],
         "notes":["This model identifies candidates only; it does not infer credentials, tokens, passwords, or valid roles."]}
    ep=root/"evidence"/"auth-intelligence-v51.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"auth-intelligence-v51.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    rp.write_text("# Authentication Intelligence (V51)\n\n> Candidate mapping only. Secrets are never collected or stored. Role boundaries require operator confirmation.\n\n"+"\n".join(f"- `{x['auth_surface']}` — `{x['endpoint']}` — likelihood **{x['auth_likelihood']}**" for x in endpoints)+"\n\n## Boundaries\n\n"+"\n".join(f"- `{b['from']}` → `{b['to']}` — **{b['confidence']}**" for b in boundaries)+"\n",encoding="utf-8")
    return ep,rp

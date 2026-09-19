#!/usr/bin/env python3
"""V46 endpoint, parameter, authentication and API intelligence."""
from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from datetime import datetime, timezone

SENSITIVE_NAMES={"id","user_id","userid","account_id","order_id","document_id","file","redirect","url","next","return","callback","token","role"}

def build(root: str|Path):
    root=Path(root); (root/"reports").mkdir(parents=True,exist_ok=True); src=root/"evidence"/"web-surface-v45.json"
    if not src.exists(): raise FileNotFoundError("V45 web surface model not found; run --web-surface first")
    data=json.loads(src.read_text(encoding="utf-8"))
    endpoints={}; auth=[]; business=[]
    for app in data.get("applications",[]):
        for url in app.get("endpoints",[]):
            p=urlparse(url); clean=f"{p.scheme}://{p.netloc}{p.path or '/'}"
            q=[k for k,_ in parse_qsl(p.query,keep_blank_values=True)]
            row=endpoints.setdefault(clean,{"endpoint":clean,"host":p.hostname,"type":"api" if app.get("api") or any(x in (p.path or '').lower() for x in ['/api','/graphql','.json']) else "web","parameters":set(),"auth_likelihood":"unknown","risk_signals":set()})
            row["parameters"].update(q)
            names=[x.lower() for x in q]
            if any(x in SENSITIVE_NAMES for x in names): row["risk_signals"].add("object-or-sensitive-parameter")
            path=(p.path or '/').lower()
            if any(x in path for x in ('login','signin','oauth','token','session')):
                row["auth_likelihood"]="likely-authentication-related"; auth.append(clean)
            if any(x in path for x in ('checkout','transfer','payment','order','profile','settings','admin')):
                business.append(clean)
    endpoint_rows=[]
    for x in endpoints.values(): endpoint_rows.append({**x,"parameters":sorted(x["parameters"]),"risk_signals":sorted(x["risk_signals"])})
    endpoint_rows.sort(key=lambda x:x["endpoint"])
    payload={"schema_version":"46.0","generated":datetime.now(timezone.utc).isoformat(),"mode":"artifact-derived",
             "endpoint_count":len(endpoint_rows),"endpoints":endpoint_rows,
             "authentication_map":sorted(set(auth)),"business_logic_candidates":sorted(set(business)),
             "parameter_priorities":sorted({p for e in endpoint_rows for p in e["parameters"] if p.lower() in SENSITIVE_NAMES})}
    ep=root/"evidence"/"web-endpoints-v46.json"; ep.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# Web/API Endpoint Intelligence (V46)","","> Derived from V45 artifacts. Authentication and business-logic items are candidates for operator review, not confirmed vulnerabilities.","",f"Endpoints: **{len(endpoint_rows)}**","", "## Priority Parameters"]
    lines += [f"- `{p}`" for p in payload["parameter_priorities"]] or ["- None observed"]
    lines += ["", "## Authentication Candidates"] + [f"- `{u}`" for u in payload["authentication_map"]] or ["- None observed"]
    lines += ["", "## Business-Logic Candidates"] + [f"- `{u}`" for u in payload["business_logic_candidates"]] or ["- None observed"]
    rp=root/"reports"/"web-endpoints-v46.md"; rp.write_text("\n".join(lines),encoding="utf-8")
    return ep,rp

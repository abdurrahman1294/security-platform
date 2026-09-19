#!/usr/bin/env python3
"""V45 structured web/API attack-surface model.

Artifact-derived only: consumes existing recon, pipeline, and finding artifacts.
It does not contact targets.
"""
from __future__ import annotations
import json, re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from datetime import datetime, timezone
from modules.findings_io import load_findings_file
from modules.atomic_io import load_json

URL_RE = re.compile(r'https?://[^\s\"\'<>]+', re.I)
API_HINTS = ("/api", "/graphql", "/swagger", "/openapi", ".json", ".xml")
AUTH_HINTS = ("login", "signin", "auth", "oauth", "token", "session", "account", "admin")

def _urls_from_text(text):
    return [m.group(0).rstrip(".,);]") for m in URL_RE.finditer(text or "")]

def _load_json(path):
    return load_json(path, None, quarantine_on_error=False)

def _iter_pipeline(root):
    d=root/"evidence"/"pipeline-results"
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        x=_load_json(p)
        if isinstance(x,dict): yield x

def _record_url(url, model, source):
    try:
        p=urlparse(url)
        if not p.hostname: return
        host=p.hostname.lower().rstrip('.')
        scheme=p.scheme.lower() or "http"
        base=f"{scheme}://{host}"
        app=model["applications"].setdefault(base,{"url":base,"host":host,"pages":set(),"endpoints":set(),"technologies":set(),"auth_hints":set(),"api":False,"sources":set()})
        app["sources"].add(source)
        path=p.path or "/"
        app["pages"].add(path)
        ep=url.split('#',1)[0]
        app["endpoints"].add(ep)
        if any(h in path.lower() for h in API_HINTS): app["api"]=True
        if any(h in path.lower() for h in AUTH_HINTS): app["auth_hints"].add("authentication-related route")
        for k,_ in parse_qsl(p.query,keep_blank_values=True):
            model["parameters"].setdefault(k,{"name":k,"count":0,"sources":set()})["count"]+=1
            model["parameters"][k]["sources"].add(ep)
    except (ValueError, TypeError, KeyError):
        return

def build(root: str|Path, target: str = ""):
    root=Path(root); (root/"evidence").mkdir(parents=True,exist_ok=True); (root/"reports").mkdir(parents=True,exist_ok=True)
    model={"domains":set(),"hosts":set(),"applications":{},"parameters":{},"technologies":defaultdict(set),"candidate_vulnerabilities":[]}
    for p in [root/"recon"/"subdomains.txt", root/"recon"/"live-hosts.txt"]:
        if p.exists():
            for line in p.read_text(errors="ignore").splitlines():
                v=line.strip();
                if v: model["hosts"].add(v.lower().split('/')[0])
    for r in _iter_pipeline(root):
        text=(r.get("stdout") or "")
        for u in _urls_from_text(text): _record_url(u,model,r.get("action","pipeline"))
        action=r.get("action")
        if action in {"http-probe","web-crawl"}:
            for u in _urls_from_text(text): _record_url(u,model,action)
    # Existing findings become candidates, never treated as confirmed by this model.
    # findings.json may be a JSON array (-json-export) or JSONL (-jsonl);
    # load_findings_file handles either, where this module's own _load_json
    # (whole-document json.loads) would break on the JSONL case.
    for p in [root/"vulns"/"findings.json",root/"vulns"/"authenticated-findings.json",root/"api"/"api-findings.json"]:
        for f in load_findings_file(p):
            info=f.get("info",{}) if isinstance(f,dict) else {}
            name=info.get("name") or f.get("template-id") or "candidate finding"
            model["candidate_vulnerabilities"].append({"name":name,"severity":info.get("severity","unknown"),"source":p.name,"status":"candidate"})
    for app in model["applications"].values():
        host=app["host"]
        model["domains"].add(host)
    out={"schema_version":"45.0","generated":datetime.now(timezone.utc).isoformat(),"target":target,
         "mode":"artifact-derived","domains":sorted(model["domains"]),"hosts":sorted(model["hosts"]),
         "applications":[],"parameters":[],"technologies":[],"candidate_vulnerabilities":model["candidate_vulnerabilities"]}
    for app in model["applications"].values():
        out["applications"].append({**app,"pages":sorted(app["pages"]),"endpoints":sorted(app["endpoints"]),"technologies":sorted(app["technologies"]),"auth_hints":sorted(app["auth_hints"]),"sources":sorted(app["sources"])})
    for x in model["parameters"].values(): out["parameters"].append({**x,"sources":sorted(x["sources"])})
    out["applications"].sort(key=lambda x:x["url"]); out["parameters"].sort(key=lambda x:x["name"])
    ep=root/"evidence"/"web-surface-v45.json"; ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    lines=["# Deep Web/API Surface Model (V45)","","> Derived from existing engagement artifacts; no network activity is performed.","",f"Target: `{target}`","",f"Applications: **{len(out['applications'])}**",f"Parameters: **{len(out['parameters'])}**",f"Candidate vulnerabilities: **{len(out['candidate_vulnerabilities'])}**","", "## Applications"]
    for a in out["applications"]:
        lines += [f"### `{a['url']}`",f"- Host: `{a['host']}`",f"- API indicators: `{a['api']}`",f"- Pages/endpoints: {len(a['pages'])}/{len(a['endpoints'])}",f"- Auth hints: {', '.join(a['auth_hints']) or 'none observed'}",""]
    rp=root/"reports"/"web-surface-v45.md"; rp.write_text("\n".join(lines),encoding="utf-8")
    return ep,rp

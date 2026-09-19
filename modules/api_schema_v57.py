#!/usr/bin/env python3
"""V57 API schema intelligence. Candidate discovery and local schema parsing only."""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

SCHEMA_HINTS=("openapi.json","openapi.yaml","openapi.yml","swagger.json","swagger.yaml","swagger.yml","api-docs","swagger-ui","docs","redoc")

def _is_url(s): return s.startswith(("http://","https://"))

def _kind(url):
    p=(urlparse(url).path or "").lower()
    if any(x in p for x in ("openapi","swagger","api-docs","swagger-ui","redoc")): return "schema-candidate"
    if "/api/" in p or p.startswith("/api") or p.endswith(".json"): return "api-candidate"
    return "web-candidate"

def build(root: str|Path):
    root=Path(root); src=root/"evidence"/"web-endpoints-v46.json"
    if not src.exists(): raise FileNotFoundError("V46 endpoint model not found; run --web-endpoints first")
    data=json.loads(src.read_text(encoding="utf-8")); endpoints=[]
    for e in data.get("endpoints",[]):
        u=e.get("endpoint","")
        if _is_url(u): endpoints.append(u)
    seen=set(); schemas=[]; api_endpoints=[]
    for u in endpoints:
        if u in seen: continue
        seen.add(u); k=_kind(u)
        if k=="schema-candidate": schemas.append({"url":u,"confidence":"high","source":"endpoint-inventory"})
        elif k=="api-candidate": api_endpoints.append(u)
    roots=sorted({f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in endpoints})
    for base in roots:
        for hint in SCHEMA_HINTS:
            schemas.append({"url":base.rstrip("/")+"/"+hint,"confidence":"candidate","source":"common-schema-location"})
    # Deduplicate schema candidates by URL.
    unique=[]; seen=set()
    for s in schemas:
        if s["url"] not in seen: seen.add(s["url"]); unique.append(s)
    local=[]
    for name in SCHEMA_HINTS:
        for p in root.rglob(name):
            if p.is_file():
                local.append({"path":str(p.relative_to(root)),"format":p.suffix.lstrip(".") or "json","source":"local-artifact"})
    out={"schema_version":"57.0","generated":datetime.now(timezone.utc).isoformat(),"api_endpoint_count":len(sorted(set(api_endpoints)),),"api_endpoints":sorted(set(api_endpoints)),"schema_candidates":unique,"local_schema_artifacts":local,"secret_values_collected":False,"human_control_required":True,"notes":["Schema discovery is candidate-based; no credentials or secrets are collected."]}
    ep=root/"evidence"/"api-schema-intelligence-v57.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"api-schema-intelligence-v57.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    lines=["# API Schema Intelligence (V57)","","> Candidate OpenAPI/Swagger discovery. No credentials or secrets are collected.","","## API candidates"]+[f"- `{u}`" for u in sorted(set(api_endpoints))]+["","## Schema candidates"]+[f"- `{s['url']}` — {s['confidence']}" for s in unique]
    rp.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return ep,rp

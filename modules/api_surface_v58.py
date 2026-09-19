#!/usr/bin/env python3
"""V58 API surface intelligence: methods, parameters, fields and trust boundaries."""
from __future__ import annotations
import json,re
from pathlib import Path
from datetime import datetime,timezone
from urllib.parse import urlparse,parse_qs

def build(root: str|Path):
    root=Path(root); src=root/"evidence"/"web-endpoints-v46.json"; schema=root/"evidence"/"api-schema-intelligence-v57.json"
    if not src.exists(): raise FileNotFoundError("V46 endpoint model not found")
    data=json.loads(src.read_text(encoding="utf-8")); sd=json.loads(schema.read_text(encoding="utf-8")) if schema.exists() else {}
    rows=[]; seen=set()
    for e in data.get("endpoints",[]):
        u=e.get("endpoint","")
        if not u.startswith(("http://","https://")) or u in seen: continue
        seen.add(u); p=urlparse(u); params=sorted(parse_qs(p.query,keep_blank_values=True).keys())
        path=(p.path or "").lower(); api=('/api/' in path or path.startswith('/api') or u in sd.get('api_endpoints',[]))
        if not api: continue
        methods=e.get("method_candidates") or ["GET"]
        rows.append({"endpoint":u,"methods":sorted(set(str(x).upper() for x in methods)),"query_parameters":params,"path_parameter_candidates":re.findall(r"\{([^}]+)\}|:([A-Za-z_][\w-]*)",p.path),"field_candidates":[],"object_reference_candidates":[x for x in params if re.search(r"(^|_)(id|uuid|user|account|order|item|object)(_|$)",x,re.I)],"auth_boundary":"operator-confirm","operator_review_required":True})
    for r in rows:
        r["path_parameter_candidates"]=[a or b for a,b in r["path_parameter_candidates"]]
    method_counts={m:sum(m in r["methods"] for r in rows) for m in ("GET","POST","PUT","PATCH","DELETE","OPTIONS")}
    out={"schema_version":"58.0","generated":datetime.now(timezone.utc).isoformat(),"endpoint_count":len(rows),"method_counts":method_counts,"endpoints":rows,"secret_values_collected":False,"destructive_tests_executed":False,"human_control_required":True,"notes":["Field-level authorization and object-reference checks are candidates for operator validation only."]}
    ep=root/"evidence"/"api-surface-intelligence-v58.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"api-surface-intelligence-v58.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    rp.write_text("# API Surface Intelligence (V58)\n\n> Methods, parameters and object-reference candidates; no destructive tests are executed.\n\n"+"\n".join(f"- `{r['endpoint']}` — {', '.join(r['methods'])} — params: {', '.join(r['query_parameters']) or 'none'}" for r in rows)+"\n",encoding="utf-8")
    return ep,rp

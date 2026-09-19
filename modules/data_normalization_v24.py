#!/usr/bin/env python3
"""V24 artifact normalization. Passive parsing only; no target interaction."""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from urllib.parse import urlparse
from modules.findings_io import load_findings_file

SOURCES=[("vulns/findings.json","web"),("vulns/authenticated-findings.json","authenticated-web"),("api/api-findings.json","api"),("servers/server-findings.json","external-server"),("internal/internal-findings.json","internal-network")]

load_jsonl = load_findings_file

def host(v):
    s=str(v or "").strip().split()[0]
    if not s:return ""
    p=urlparse(s if "://" in s else "//"+s)
    return (p.hostname or s.split("/",1)[0]).lower().rstrip(".")

def normalize(f,source,index):
    info=f.get("info") or {}
    title=str(info.get("name") or f.get("name") or f.get("template-id") or f.get("id") or "Untitled finding").strip()
    severity=str(info.get("severity") or f.get("severity") or "info").lower().strip()
    if severity not in {"critical","high","medium","low","info"}: severity="info"
    asset=host(f.get("host") or f.get("matched-at") or f.get("url")) or "unknown-asset"
    endpoint=str(f.get("matched-at") or f.get("url") or "").strip()
    template=str(f.get("template-id") or f.get("template_id") or "").strip()
    desc=str(info.get("description") or f.get("description") or "").strip()
    seed="|".join([title.lower(),severity,asset,endpoint,template])
    fid="F-"+hashlib.sha256(seed.encode()).hexdigest()[:12]
    return {"normalized_id":fid,"title":title,"severity":severity,"asset":asset,"endpoint":endpoint,"template_id":template,"description":desc[:5000],"surface":source,"source_record":index,"raw_fields":sorted(str(k) for k in f.keys())}

def build(root):
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True)
    rows=[]
    for rel,surface in SOURCES:
        for i,f in enumerate(load_jsonl(root/rel)):
            rows.append(normalize(f,surface,i))
    unique={r["normalized_id"]:r for r in rows}
    payload={"schema_version":"1.0","mode":"artifact-derived","records_seen":len(rows),"records_normalized":len(unique),"findings":list(unique.values())}
    p=ev/"normalized-findings.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# V24 Normalized Findings","","> Derived from existing artifacts. No network activity is performed.","",f"Records seen: **{len(rows)}**",f"Normalized unique findings: **{len(unique)}**","", "| ID | Severity | Surface | Asset | Title |","|---|---|---|---|---|"]
    for r in unique.values(): lines.append(f"| `{r['normalized_id']}` | `{r['severity']}` | `{r['surface']}` | `{r['asset']}` | {r['title'].replace('|','/')} |")
    (rep/"normalized-findings.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return p

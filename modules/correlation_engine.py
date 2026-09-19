#!/usr/bin/env python3
"""V16 normalized finding correlation and uncertainty analysis.

Decision support only. No exploit generation or target interaction.
"""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from urllib.parse import urlparse
from modules.findings_io import load_findings_file

SURFACES={"findings.json":"web","authenticated-findings.json":"authenticated-web","api-findings.json":"api","server-findings.json":"external-server","internal-findings.json":"internal-network"}

_load_jsonl = load_findings_file

def _host(f):
    v=str(f.get("host") or f.get("matched-at") or "")
    p=urlparse(v if "://" in v else "//"+v)
    return (p.hostname or v.split("/",1)[0]).lower().rstrip(".")

def _fid(f):
    seed="|".join([str(f.get("template-id") or f.get("id") or ""),_host(f),str(f.get("matched-at") or ""),str((f.get("info") or {}).get("name") or "")])
    return "F-"+hashlib.sha256(seed.encode()).hexdigest()[:12]

def _key(f):
    info=f.get("info") or {}; name=str(info.get("name") or f.get("template-id") or "").lower()
    name=re.sub(r"[^a-z0-9]+"," ",name).strip()
    return (name,_host(f),str(info.get("severity") or "info").lower())

def build(root: str|Path):
    root=Path(root); evidence=root/"evidence"; evidence.mkdir(parents=True,exist_ok=True)
    findings=[]
    for p in [root/"vulns"/"findings.json",root/"vulns"/"authenticated-findings.json",root/"api"/"api-findings.json",root/"servers"/"server-findings.json",root/"internal"/"internal-findings.json"]:
        for f in _load_jsonl(p):
            f=dict(f); f["correlation_id"]=_fid(f); f["surface"]=SURFACES.get(p.name,p.parent.name); f["asset"]=_host(f); findings.append(f)
    clusters={}
    for f in findings:
        clusters.setdefault(_key(f),[]).append(f["correlation_id"])
    duplicates=[]; groups=[]
    for key,ids in clusters.items():
        if len(ids)>1:
            gid="C-"+hashlib.sha256("|".join(ids).encode()).hexdigest()[:10]
            groups.append({"cluster_id":gid,"reason":"same normalized title/asset/severity","finding_ids":ids})
            for fid in ids[1:]: duplicates.append({"source":fid,"target":ids[0],"relation":"possible-duplicate","status":"hypothesis","confidence":0.78})
    by_asset={}
    for f in findings: by_asset.setdefault(f["asset"],[]).append(f)
    relationships=[]
    for asset,fs in by_asset.items():
        if len(fs)>1:
            for i,a in enumerate(fs):
                for b in fs[i+1:]:
                    if a["surface"]!=b["surface"]:
                        relationships.append({"source":a["correlation_id"],"target":b["correlation_id"],"relation":"cross-surface-same-asset","status":"hypothesis","confidence":0.72,"rationale":"Findings affect the same observed asset but exploitability/causality is not established."})
    # Same registered parent domain is a weaker hypothesis than same-asset correlation.
    def parent(h):
        parts=[x for x in str(h).split(".") if x]
        return ".".join(parts[-2:]) if len(parts)>=2 else str(h)
    domain_groups={}
    for f in findings: domain_groups.setdefault(parent(f["asset"]),[]).append(f)
    for domain,fs in domain_groups.items():
        for i,a in enumerate(fs):
            for b in fs[i+1:]:
                if a["asset"]!=b["asset"] and a["surface"]!=b["surface"]:
                    relationships.append({"source":a["correlation_id"],"target":b["correlation_id"],"relation":"same-parent-domain","status":"hypothesis","confidence":0.55,"rationale":"Assets share an observed parent domain; backend ownership or trust is not established."})
    payload={"schema_version":"1.0","finding_count":len(findings),"clusters":groups,"duplicate_hypotheses":duplicates,"cross_surface_relationships":relationships}
    path=evidence/"correlation.json"; path.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# Finding Correlation","","> Correlations are hypotheses for analyst review; they do not prove causality or exploitation.",""]
    lines.append(f"Findings analyzed: **{len(findings)}**")
    lines.append(f"Potential duplicate clusters: **{len(groups)}**")
    lines.append(f"Cross-surface hypotheses: **{len(relationships)}**\n")
    for g in groups: lines += [f"## {g['cluster_id']}","- " + ", ".join(f"`{x}`" for x in g["finding_ids"]),""]
    (root/"reports"/"correlation.md").write_text("\n".join(lines),encoding="utf-8")
    return path

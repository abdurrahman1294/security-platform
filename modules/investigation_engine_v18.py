#!/usr/bin/env python3
"""Advanced, human-in-the-loop investigation prioritization."""
from __future__ import annotations
import json
from pathlib import Path

SEV={"critical":1.0,"high":.85,"medium":.65,"low":.4,"info":.2}
STATUS={"confirmed":1.0,"validated":.9,"candidate":.75,"unreviewed":.6,"inconclusive":.45,"blocked":.2,"accepted-risk":.25,"false-positive":0.0}

def _load(p, default):
    try: return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
    except (OSError, json.JSONDecodeError): return default

def build(root: str|Path, limit: int=15) -> Path:
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; rep.mkdir(parents=True,exist_ok=True)
    graph=_load(ev/"attack-graph.json",{"nodes":[],"edges":[]})
    assets=_load(ev/"assets.json",{"assets":[]}); impact=_load(ev/"business-impact.json",{})
    findings=[n for n in graph.get("nodes",[]) if n.get("type")=="finding" and n.get("status")!="false-positive"]
    edges=graph.get("edges",[]); asset_map={str(a.get("host") or a.get("asset_id")):a for a in assets.get("assets",[])}
    out=[]
    for n in findings:
        fid=n.get("finding_id") or n.get("id"); meta=n.get("metadata") or {}; asset=n.get("asset") or ""
        related=sum(1 for e in edges if e.get("source") in {n.get("id"),fid} or e.get("target") in {n.get("id"),fid})
        prereqs=meta.get("prerequisites") or n.get("prerequisites") or []
        missing=sum(1 for p in prereqs if isinstance(p,dict) and not p.get("satisfied",False))
        eq=float(meta.get("evidence_quality",0.45) or 0.45); conf=float(n.get("confidence",meta.get("confidence",0.5)) or .5)
        sev=SEV.get(str(n.get("severity","info")).lower(),.2); status=STATUS.get(str(n.get("status","unreviewed")).lower(),.6)
        a=asset_map.get(str(asset),{}); importance=str((impact.get(fid) or impact.get(str(fid)) or {}).get("asset_importance", a.get("importance","low"))).lower()
        imp=SEV.get(importance,.4)
        uncertainty=1-min(1,eq*.7+conf*.3)
        validation_value=min(1, .5*uncertainty + .25*min(1,related/4) + .25*(1 if n.get("status") not in {"confirmed","validated"} else .3))
        blocked_penalty=0.45 if missing else 1.0
        score=100*blocked_penalty*(.25*sev+.18*eq+.17*conf+.14*status+.12*min(1,related/4)+.08*imp+.06*validation_value)
        if n.get("status") in {"confirmed","validated"}: action="Assess impact, preserve evidence, and review connected hypotheses before further validation."
        elif missing: action=f"Resolve {missing} unsatisfied prerequisite(s) before validation."
        else: action="Use Controlled Validation with the least-invasive suitable mode and capture reproducible evidence."
        out.append({"finding_id":fid,"title":n.get("label"),"asset":asset,"severity":n.get("severity"),"status":n.get("status"),"confidence":round(conf,3),"evidence_quality":round(eq,3),"related_count":related,"missing_prerequisites":missing,"asset_importance":importance,"uncertainty":round(uncertainty,3),"validation_value":round(validation_value,3),"priority":round(score,1),"recommended_action":action})
    out.sort(key=lambda x:(-x["priority"],str(x["finding_id"])))
    payload={"schema_version":"1.1","engine":"advanced-investigation-v18","recommendations":out[:limit]}
    p=ev/"investigation-priorities-v18.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# Advanced Investigation Priorities (V18)","","> Advisory decision support for an authorized tester. No exploitation or automatic pivoting is performed.",""]
    for i,r in enumerate(out[:limit],1):
        lines += [f"## {i}. {r['title']} — `{r['finding_id']}`",f"- Priority: **{r['priority']} / 100**",f"- Severity: `{r['severity']}` · Status: `{r['status']}` · Confidence: `{r['confidence']}`",f"- Evidence quality: `{r['evidence_quality']}` · Related findings: `{r['related_count']}`",f"- Missing prerequisites: `{r['missing_prerequisites']}` · Asset importance: `{r['asset_importance']}`",f"- Validation value: `{r['validation_value']}`",f"- **Next step:** {r['recommended_action']}",""]
    (rep/"investigation-priorities-v18.md").write_text("\n".join(lines),encoding="utf-8")
    return p

#!/usr/bin/env python3
"""V22 risk, blast-radius and attack-path analytics. Decision support only."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
SEV={"critical":1.0,"high":.85,"medium":.65,"low":.4,"info":.2}
STATE={"confirmed":1.0,"validated":.9,"validating":.75,"candidate":.6,"unreviewed":.55,"inconclusive":.4,"blocked":.2,"accepted-risk":.25,"false-positive":0}

def _load(p,d):
    try:return json.loads(p.read_text(encoding="utf-8")) if p.exists() else d
    except (OSError,json.JSONDecodeError):return d

def build(root: str|Path) -> Path:
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; rep.mkdir(parents=True,exist_ok=True)
    g=_load(ev/"attack-graph.json",{"nodes":[],"edges":[]}); impacts=_load(ev/"business-impact.json",{}); assets=_load(ev/"assets.json",{"assets":[]}); ret=_load(ev/"retest-ledger.json",[])
    findings=[n for n in g.get("nodes",[]) if n.get("type")=="finding" and n.get("status")!="false-positive"]
    asset_nodes=[n for n in g.get("nodes",[]) if n.get("type")=="asset"]
    by_asset={}
    for n in findings: by_asset.setdefault(str(n.get("asset") or "unknown"),[]).append(n)
    asset_rows=[]
    for asset, fs in by_asset.items():
        sev=max((SEV.get(str(f.get("severity","info")).lower(),.2) for f in fs),default=.2)
        confirmed=sum(1 for f in fs if f.get("status")=="confirmed")
        blast=min(1.0, len(fs)/5 + confirmed/5)
        asset_rows.append({"asset":asset,"finding_count":len(fs),"confirmed_count":confirmed,"max_severity":max(fs,key=lambda f:SEV.get(str(f.get("severity","info")).lower(),.2)).get("severity") if fs else "info","blast_radius":round(blast,2)})
    paths=[]
    for e in g.get("edges",[]):
        if e.get("status") not in {"observed","workflow","hypothesis"}: continue
        s=next((f for f in findings if f.get("id")==e.get("source")),None); t=next((f for f in findings if f.get("id")==e.get("target")),None)
        if not s or not t: continue
        conf=min(float(s.get("confidence",.5) or .5),float(t.get("confidence",.5) or .5),float(e.get("confidence",.5) or .5))
        state=min(STATE.get(str(s.get("status","unreviewed")),.5),STATE.get(str(t.get("status","unreviewed")),.5))
        score=round(100*conf*state*max(SEV.get(str(s.get("severity","info")).lower(),.2),SEV.get(str(t.get("severity","info")).lower(),.2)),1)
        paths.append({"source":s.get("finding_id") or s.get("id"),"target":t.get("finding_id") or t.get("id"),"status":e.get("status"),"confidence":round(conf,2),"path_risk":score})
    remediation=[]
    for f in findings:
        fid=str(f.get("finding_id") or f.get("id")); imp=impacts.get(fid,{})
        business=max({"critical":1,"high":.85,"medium":.65,"low":.4}.get(str(imp.get("asset_importance","low")),.4), {"critical":1,"confidential":.8,"internal":.55,"public":.25,"unknown":.35}.get(str(imp.get("data_sensitivity","unknown")),.35))
        risk=round(100*SEV.get(str(f.get("severity","info")).lower(),.2)*float(f.get("confidence",.5) or .5)*business,1)
        remediation.append({"finding_id":fid,"title":f.get("label"),"risk_score":risk,"asset":f.get("asset"),"status":f.get("status"),"business_context":imp})
    remediation.sort(key=lambda x:(-x["risk_score"],x["finding_id"]))
    payload={"schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),"findings_analyzed":len(findings),"asset_risk":asset_rows,"attack_path_risk":sorted(paths,key=lambda x:-x["path_risk"]),"remediation_priority":remediation[:50],"retest_count":len(ret)}
    p=ev/"risk-analytics-v22.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# V22 Risk & Attack-Path Analytics","",f"Findings analyzed: **{len(findings)}**",f"Retest records: **{len(ret)}**","","## Remediation priority","","| Finding | Risk | Status | Asset |","|---|---:|---|---|"]+[f"| `{r['finding_id']}` | **{r['risk_score']}** | `{r['status']}` | `{r['asset']}` |" for r in remediation[:20]]
    lines += ["","## Asset blast radius","","| Asset | Findings | Confirmed | Max severity | Blast radius |","|---|---:|---:|---|---:|"]+[f"| `{a['asset']}` | {a['finding_count']} | {a['confirmed_count']} | `{a['max_severity']}` | {a['blast_radius']} |" for a in asset_rows]
    lines += ["","## Candidate path risk","","| Source | Target | State | Risk |","|---|---|---|---:|"]+[f"| `{x['source']}` | `{x['target']}` | `{x['status']}` | {x['path_risk']} |" for x in sorted(paths,key=lambda x:-x['path_risk'])[:30]]
    (rep/"risk-analytics-v22.md").write_text("\n".join(lines)+"\n",encoding="utf-8"); return p

#!/usr/bin/env python3
"""Human-in-the-loop investigation prioritization.

Produces recommendations only. It never generates or executes exploit/pivot commands.
"""
from __future__ import annotations
import json
from pathlib import Path

SEV={"critical":1.0,"high":0.85,"medium":0.65,"low":0.4,"info":0.2}
STATUS={"confirmed":1.0,"unreviewed":0.65,"accepted-risk":0.35,"false-positive":0.0}

def recommend(outdir: str | Path, limit: int=10) -> Path:
    root=Path(outdir); graphp=root/"evidence"/"attack-graph.json"; data={"nodes":[],"edges":[]}
    if graphp.exists():
        try: data=json.loads(graphp.read_text())
        except json.JSONDecodeError: pass
    findings=[n for n in data.get("nodes",[]) if n.get("type")=="finding"]
    incoming={n.get("id"):0 for n in findings}; related={n.get("id"):0 for n in findings}
    for e in data.get("edges",[]):
        if e.get("target") in incoming: incoming[e["target"]]+=1
        if e.get("source") in related: related[e["source"]]+=1
    recs=[]
    for n in findings:
        if n.get("status")=="false-positive": continue
        m=n.get("metadata") or {}; eq=float(m.get("evidence_quality",0.45)); sev=SEV.get(n.get("severity","info"),.2); st=STATUS.get(n.get("status","unreviewed"),.65)
        score=round(100*(0.40*sev+0.25*eq+0.15*st+0.10*min(1,incoming.get(n["id"],0)/3)+0.10*min(1,related.get(n["id"],0)/3)),1)
        if n.get("status")=="confirmed": action="Assess impact and document the confirmed condition before pursuing related hypotheses."
        elif eq < .7: action="Manually validate the finding and capture minimal reproducible evidence."
        else: action="Review prerequisites and determine whether a safe, authorized validation is warranted."
        recs.append({"rank_score":score,"finding_id":n.get("finding_id") or n.get("id"),"title":n.get("label"),"asset":n.get("asset"),"severity":n.get("severity"),"status":n.get("status"),"confidence":n.get("confidence"),"evidence_quality":eq,"reason":action,"relationship_count":incoming.get(n["id"],0)+related.get(n["id"],0)})
    recs.sort(key=lambda x:(-x["rank_score"],x["finding_id"] or "")); recs=recs[:limit]
    payload={"schema_version":"1.0","method":"risk + evidence + relationship prioritization","recommendations":recs}
    path=root/"evidence"/"next-investigation.json"; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# What Should I Investigate Next?","","> Recommendations are decision support for an authorized tester. They do not constitute proof and do not execute testing.",""]
    for i,r in enumerate(recs,1):
        lines += [f"## {i}. {r['title']} — `{r['finding_id']}`",f"- Score: **{r['rank_score']} / 100**",f"- Asset: `{r['asset']}`",f"- Severity: `{r['severity']}` | Status: `{r['status']}` | Confidence: `{r['confidence']}`",f"- Evidence quality: `{r['evidence_quality']}`",f"- Relationships: `{r['relationship_count']}`",f"- **Recommended next step:** {r['reason']}",""]
    (root/"reports"/"next-investigation.md").write_text("\n".join(lines),encoding="utf-8")
    return path

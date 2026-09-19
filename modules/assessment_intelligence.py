#!/usr/bin/env python3
"""V11 assessment intelligence: prioritization, prerequisites, queue and business impact.

Decision support only. This module never executes testing or exploit actions.
"""
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

SEV = {"critical": 1.0, "high": .85, "medium": .65, "low": .4, "info": .2}
STATUS = {"confirmed":1.0,"validated":.9,"validating":.75,"candidate":.65,"unreviewed":.6,"inconclusive":.45,"accepted-risk":.35,"blocked":.2,"false-positive":0.0}
BUSINESS = {"critical":1.0,"high":.85,"medium":.65,"low":.4}
DATA = {"critical":1.0,"confidential":.8,"internal":.55,"public":.25,"unknown":.35}


def _load(path, default):
    if not path.exists(): return default
    try:
        x=json.loads(path.read_text(encoding="utf-8")); return x
    except (OSError,json.JSONDecodeError): return default


def _graph(root): return _load(root/"evidence"/"attack-graph.json", {"nodes":[],"edges":[]})


def _impact_map(root): return _load(root/"evidence"/"business-impact.json", {})


def _validation(root):
    return _load(root/"evidence"/"validation-ledger.json", [])


def _evidence_score(node):
    return float((node.get("metadata") or {}).get("evidence_quality", .45) or .45)


def _relationship_score(fid, edges):
    count=0
    for e in edges:
        if e.get("source")==fid or e.get("target")==fid:
            if e.get("status") in {"hypothesis","workflow","observed"}: count += 1
    return min(1.0, count/4)


def _validation_value(node, impact):
    # High uncertainty + high consequence = high information value.
    uncertainty = 1.0 - float(node.get("confidence",0) or 0)
    consequence = max(SEV.get(node.get("severity","info"),.2), BUSINESS.get(impact.get("asset_importance","low"),.4), DATA.get(impact.get("data_sensitivity","unknown"),.35))
    return min(1.0, .35*uncertainty + .65*consequence)


def calculate(root: Path, limit: int=20):
    graph=_graph(root); impacts=_impact_map(root); edges=graph.get("edges",[])
    rows=[]
    for n in graph.get("nodes",[]):
        if n.get("type")!="finding" or n.get("status")=="false-positive": continue
        fid=n.get("finding_id") or n.get("id"); imp=impacts.get(fid,{})
        sev=SEV.get(str(n.get("severity","info")).lower(),.2)
        evidence=_evidence_score(n); status=STATUS.get(str(n.get("status","unreviewed")),.5)
        relation=_relationship_score(n.get("id"),edges)
        business=max(BUSINESS.get(str(imp.get("asset_importance","low")),.4), DATA.get(str(imp.get("data_sensitivity","unknown")),.35))
        value=_validation_value(n,imp)
        score=round(100*(.24*sev+.18*evidence+.16*status+.16*relation+.16*business+.10*value),1)
        if n.get("status")=="confirmed": action="Assess impact, preserve evidence, and review related hypotheses rather than re-validating the confirmed condition."
        elif n.get("status") in {"blocked","inconclusive"}: action="Resolve the blocker or uncertainty, then decide whether a safe controlled validation is warranted."
        else: action="Use Controlled Validation to safely reduce uncertainty and capture minimal reproducible evidence."
        rows.append({"rank_score":score,"finding_id":fid,"title":n.get("label"),"asset":n.get("asset"),"severity":n.get("severity"),"status":n.get("status"),"confidence":n.get("confidence"),"evidence_quality":evidence,"relationship_score":round(relation,2),"business_score":round(business,2),"validation_value":round(value,2),"reason":action,"prerequisites":(n.get("metadata") or {}).get("prerequisites",[])})
    rows.sort(key=lambda x:(-x["rank_score"],x["finding_id"] or ""))
    return rows[:limit]


def build(root: str|Path, limit:int=20):
    root=Path(root); (root/"reports").mkdir(parents=True,exist_ok=True); recs=calculate(root,limit); now=datetime.now(timezone.utc).isoformat()
    payload={"schema_version":"2.0","generated_at":now,"method":"severity + evidence + status + relationships + business context + validation value","recommendations":recs}
    ep=root/"evidence"/"assessment-priorities.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    queue=[dict(r, queue_status="ready" if r["status"] not in {"confirmed","false-positive"} else "review") for r in recs]
    qp=root/"evidence"/"validation-queue.json"; qp.write_text(json.dumps({"schema_version":"1.0","generated_at":now,"queue":queue},indent=2),encoding="utf-8")
    lines=["# V11 Assessment Intelligence","","> Decision support only. Recommendations never authorize or execute testing.","","## Investigation priorities",""]
    for i,r in enumerate(recs,1):
        lines += [f"### {i}. {r['title']} — `{r['finding_id']}`",f"- **Priority:** {r['rank_score']}/100",f"- **Severity:** `{r['severity']}` | **Status:** `{r['status']}` | **Confidence:** `{r['confidence']}`",f"- **Evidence:** `{r['evidence_quality']}` | **Relationships:** `{r['relationship_score']}` | **Business:** `{r['business_score']}` | **Validation value:** `{r['validation_value']}`",f"- **Next step:** {r['reason']}"]
        if r.get("prerequisites"): lines.append("- **Prerequisites:** " + "; ".join(r["prerequisites"]))
        lines.append("")
    (root/"reports"/"assessment-intelligence.md").write_text("\n".join(lines),encoding="utf-8")
    qlines=["# Controlled Validation Queue","","Each item requires separate authorization, scope verification, and explicit operator approval.",""]
    for i,r in enumerate(queue,1): qlines.append(f"{i}. `{r['finding_id']}` — **{r['title']}** — priority **{r['rank_score']}** — `{r['queue_status']}`")
    (root/"reports"/"validation-queue.md").write_text("\n".join(qlines)+"\n",encoding="utf-8")
    return ep,qp


def set_business_impact(root: str|Path, finding_id: str, asset_importance: str="low", data_sensitivity: str="unknown", business_function: str="", note: str=""):
    asset_importance=asset_importance.lower(); data_sensitivity=data_sensitivity.lower()
    if asset_importance not in BUSINESS: raise ValueError("asset_importance must be critical/high/medium/low")
    if data_sensitivity not in DATA: raise ValueError("data_sensitivity must be critical/confidential/internal/public/unknown")
    root=Path(root); path=root/"evidence"/"business-impact.json"; data=_impact_map(root)
    data[finding_id]={"asset_importance":asset_importance,"data_sensitivity":data_sensitivity,"business_function":business_function.strip(),"note":note.strip(),"updated":datetime.now(timezone.utc).isoformat()}
    path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(data,indent=2),encoding="utf-8")
    return path

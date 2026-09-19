#!/usr/bin/env python3
"""V32 final residual-risk posture after controlled proof and retest."""
from __future__ import annotations
import json
from .atomic_io import load_json
from datetime import datetime,timezone
from pathlib import Path

def _load(p,d):
    if not p.exists(): return d
    return load_json(p, d)

def build(root: str|Path):
    root=Path(root)
    findings=_load(root/"evidence"/"normalized-findings.json",[]); findings=findings.get("findings",[]) if isinstance(findings,dict) else findings
    retests=_load(root/"evidence"/"retest-intelligence.json",[]); retests=retests.get("findings",retests) if isinstance(retests,dict) else retests
    proofs=_load(root/"evidence"/"controlled-exploitation.json",[])
    proof_by={x.get("finding_id"):x for x in proofs if isinstance(x,dict)}
    retest_by={x.get("finding_id"):x for x in retests if isinstance(x,dict)}
    blockers=[]; rows=[]
    weight={"critical":10,"high":7,"medium":4,"low":1,"info":0}
    score=0
    for f in findings if isinstance(findings,list) else []:
        fid=f.get("finding_id") or f.get("id"); sev=str(f.get("severity") or f.get("info",{}).get("severity","info")).lower(); status=str(f.get("status","unreviewed")).lower()
        proof=proof_by.get(fid,{}); retest=retest_by.get(fid,{})
        state=retest.get("state") or retest.get("result") or "not-retested"
        residual=weight.get(sev,0)
        if state in {"fixed","remediated"}: residual=0
        elif state in {"partially-fixed","residual-risk"}: residual=max(1,residual//2)
        if status in {"false-positive","accepted-risk"}: residual=0
        if sev in {"critical","high"} and residual>0: blockers.append({"finding_id":fid,"severity":sev,"reason":"High residual risk remains"})
        if proof.get("result")=="confirmed" and residual>0: residual+=1
        score+=residual; rows.append({"finding_id":fid,"severity":sev,"status":status,"proof_result":proof.get("result","not-tested"),"retest_state":state,"residual_score":residual})
    posture="BLOCKED" if blockers else ("CONDITIONAL" if score else "READY")
    payload={"schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),"posture":posture,"residual_score":score,"closure_blockers":blockers,"findings":rows,"human_decision_required":True}
    p=root/"evidence"/"assessment-decision.json"; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    rp=root/"reports"/"assessment-decision.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    lines=["# Final Assessment Decision (V32)","",f"**Posture:** **{posture}**",f"**Residual score:** **{score}**", "", "## Important", "This is decision support only. Final acceptance, risk acceptance, and closure remain human decisions.", "", "## Closure blockers"]
    lines += [f"- `{b['finding_id']}` — {b['severity']}: {b['reason']}" for b in blockers] or ["- None detected by the engine."]
    rp.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return p

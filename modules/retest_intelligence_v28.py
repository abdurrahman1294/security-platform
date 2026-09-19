#!/usr/bin/env python3
"""V28 retest intelligence: compare recorded evidence/status metadata only."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

def _load(p,d):
    try:return json.loads(p.read_text(encoding="utf-8")) if p.exists() else d
    except (OSError,json.JSONDecodeError):return d

def build(root):
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True)
    ret=_load(ev/"retest-ledger.json",[]); rem=_load(ev/"remediation-tracking.json",{"records":[]})
    latest={}
    for r in ret if isinstance(ret,list) else []: latest[r.get("finding_id")]=r
    tracking={}
    for r in rem.get("records",[]): tracking[r.get("finding_id")]=r
    rows=[]
    for fid in sorted(set(latest)|set(tracking)):
        r=latest.get(fid,{}); t=tracking.get(fid,{})
        result=r.get("result","not-retested")
        outcome={"fixed":"remediated","partially-fixed":"residual-risk","still-present":"unresolved","inconclusive":"needs-review","not-retested":"awaiting-retest"}.get(result,"needs-review")
        rows.append({"finding_id":fid,"latest_retest_result":result,"assessment":outcome,"remediation_status":t.get("status","not-tracked"),"evidence":r.get("evidence",[]),"last_retest_at":r.get("timestamp"),"residual_risk": outcome in {"residual-risk","unresolved","needs-review"}})
    payload={"schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),"findings":rows}
    p=ev/"retest-intelligence.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# V28 Retest Intelligence","","| Finding | Latest Result | Assessment | Remediation | Residual Risk |","|---|---|---|---|---|"]
    for x in rows: lines.append(f"| `{x['finding_id']}` | `{x['latest_retest_result']}` | `{x['assessment']}` | `{x['remediation_status']}` | {'YES' if x['residual_risk'] else 'NO'} |")
    (rep/"retest-intelligence.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return p

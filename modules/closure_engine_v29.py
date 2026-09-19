#!/usr/bin/env python3
"""V29 closure readiness engine. It evaluates artifacts and unresolved risk; no testing."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

def _load(p,d):
    try:return json.loads(p.read_text(encoding="utf-8")) if p.exists() else d
    except (OSError,json.JSONDecodeError):return d

def build(root):
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True)
    checks=[]
    required=[("engagement","engagement.json"),("assets","assets.json"),("evidence","evidence-index.json"),("findings","normalized-findings.json"),("attack_graph","attack-graph.json"),("report_pack","../reports/report-pack.md")]
    for name,rel in required: checks.append({"check":name,"ok":(ev/rel).exists()})
    ret=_load(ev/"retest-intelligence.json",{"findings":[]}); unresolved=[x for x in ret.get("findings",[]) if x.get("residual_risk")]
    open_cases=[]
    cases=_load(ev/"case-ledger.json",[])
    if isinstance(cases,list): open_cases=[x for x in cases if x.get("status") not in {"closed","accepted-risk"}]
    checks += [{"check":"retest_intelligence","ok":(ev/"retest-intelligence.json").exists()},{"check":"no_unresolved_retest_risk","ok":not unresolved},{"check":"case_review","ok":not open_cases}]
    ready=all(c["ok"] for c in checks)
    payload={"schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),"ready_to_close":ready,"checks":checks,"unresolved_retest_findings":[x["finding_id"] for x in unresolved],"open_cases_count":len(open_cases),"decision":"READY" if ready else "NOT_READY"}
    p=ev/"closure-readiness.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# V29 Engagement Closure Readiness","",f"**Decision:** {'READY' if ready else 'NOT READY'}","","> Closure readiness is an assessment aid. An operator remains responsible for the final engagement decision.","","| Check | Status |","|---|---|"]+[f"| `{c['check']}` | {'PASS' if c['ok'] else 'BLOCKED'} |" for c in checks]
    if unresolved: lines += ["","## Residual retest risk",""]+[f"- `{x['finding_id']}` — `{x['assessment']}`" for x in unresolved]
    (rep/"closure-readiness.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return p

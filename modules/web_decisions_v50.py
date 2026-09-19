#!/usr/bin/env python3
"""V50: adaptive web/API decisions from V48 plans and V49 observations."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

def build(root: str|Path):
    root=Path(root); matrix=root/"evidence"/"web-test-matrix-v48.json"; probe=root/"evidence"/"web-probe-v49.json"
    if not matrix.exists(): raise FileNotFoundError("V48 matrix not found")
    m=json.loads(matrix.read_text(encoding="utf-8")); p=json.loads(probe.read_text(encoding="utf-8")) if probe.exists() else {"results":[]}
    observed={x.get("url"):x for x in p.get("results",[])}; decisions=[]
    for t in m.get("tests",[]):
        r=observed.get(t.get("target")); action="review-and-validate"
        reason="No bounded observation yet; operator review remains required."
        if r and r.get("status")=="observed":
            if t.get("category")=="Security configuration":
                missing=[k for k,v in (r.get("security_headers") or {}).items() if not v]
                action="review-security-headers" if missing else "review-header-baseline"
                reason=f"Observed missing baseline headers: {', '.join(missing) or 'none'}"
            else:
                action="operator-validate-candidate"
                reason="Target responded to a bounded GET; this is not proof of a vulnerability."
        decisions.append({"test_case":t.get("test_case"),"category":t.get("category"),"target":t.get("target"),"priority":t.get("priority"),"next_action":action,"reason":reason,"human_control_required":True})
    decisions.sort(key=lambda x:{"high":0,"medium":1,"low":2}.get(x.get("priority"),9))
    out={"schema_version":"50.0","generated":datetime.now(timezone.utc).isoformat(),"decision_only":True,"human_control_required":True,"decisions":decisions}
    ep=root/"evidence"/"web-decisions-v50.json"; ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"web-decisions-v50.md"; rp.write_text("# Adaptive Web/API Decisions (V50)\n\n> Decision support only; no item authorizes exploitation or mutation.\n\n"+"\n".join(f"- **{x['priority']}** `{x['category']}` — `{x['next_action']}` — {x['reason']}" for x in decisions)+"\n",encoding="utf-8")
    return ep,rp

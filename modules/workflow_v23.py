#!/usr/bin/env python3
"""V23 engagement lifecycle state machine with explicit gates."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
STAGES=["planning","recon","analysis","validation","evidence","reporting","remediation","retest","closure"]

def _load(p,d):
    try:return json.loads(p.read_text(encoding="utf-8")) if p.exists() else d
    except (OSError,json.JSONDecodeError):return d

def _gates(root, stage):
    ev=root/"evidence"; rep=root/"reports"
    files={
      "planning":[ev/"engagement.json"],
      "recon":[],
      "analysis":[ev/"attack-graph.json",ev/"assets.json"],
      "validation":[ev/"validation-queue.json"],
      "evidence":[ev/"evidence-index.json"],
      "reporting":[rep/"report-pack.md"],
      "remediation":[ev/"case-ledger.json"],
      "retest":[ev/"retest-ledger.json"],
      "closure":[ev/"engagement-readiness.json",rep/"report-pack.md"],
    }
    return [{"artifact":str(p.relative_to(root)),"ok":p.exists()} for p in files.get(stage,[])]

def status(root: str|Path) -> Path:
    root=Path(root); p=root/"evidence"/"workflow.json"; data=_load(p,{"stage":"planning","history":[]})
    gates=_gates(root,data.get("stage","planning")); data["gates"]=gates; data["can_advance"]=all(g["ok"] for g in gates); data["updated_at"]=datetime.now(timezone.utc).isoformat()
    p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(data,indent=2),encoding="utf-8"); _report(root,data); return p

def advance(root: str|Path, approved: bool=False) -> Path:
    if not approved: raise PermissionError("Explicit operator approval is required")
    root=Path(root); p=status(root); data=_load(p,{"stage":"planning","history":[]}); cur=data.get("stage","planning"); idx=STAGES.index(cur)
    if idx>=len(STAGES)-1: raise RuntimeError("Engagement is already at closure")
    gates=_gates(root,cur)
    if not all(g["ok"] for g in gates): raise RuntimeError("Current workflow stage has unmet gates")
    nxt=STAGES[idx+1]; data.setdefault("history",[]).append({"from":cur,"to":nxt,"timestamp":datetime.now(timezone.utc).isoformat(),"approved":True}); data["stage"]=nxt
    p.write_text(json.dumps(data,indent=2),encoding="utf-8"); return status(root)

def _report(root,data):
    lines=["# V23 Engagement Workflow","",f"**Current stage:** `{data.get('stage')}`",f"**Can advance:** {'YES' if data.get('can_advance') else 'NO'}","","## Gates","","| Artifact | Status |","|---|---|"]+[f"| `{g['artifact']}` | {'PASS' if g['ok'] else 'BLOCKED'} |" for g in data.get('gates',[])]
    lines += ["","## History",""]+[f"- `{h['from']}` → `{h['to']}` — {h['timestamp']}" for h in data.get('history',[])]
    lines += ["","### Lifecycle","", " → ".join(STAGES)]
    (root/"reports").mkdir(parents=True,exist_ok=True); (root/"reports"/"engagement-workflow.md").write_text("\n".join(lines)+"\n",encoding="utf-8")

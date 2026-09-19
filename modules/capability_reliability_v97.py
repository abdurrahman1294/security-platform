from __future__ import annotations
import json
from pathlib import Path

def build(root):
 root=Path(root); e=root/'evidence'; ledger=e/'tool-execution-ledger-v40.json'; stats={}
 if ledger.exists():
  for r in json.loads(ledger.read_text()):
   t=r.get('tool_id','unknown'); s=stats.setdefault(t,{'runs':0,'completed':0,'failed':0,'timeout':0})
   s['runs']+=1; st=r.get('status'); s[st]=s.get(st,0)+1
 for s in stats.values(): s['success_rate']=round((s.get('completed',0)/s['runs'])*100,2) if s['runs'] else 0
 out={'version':'V97','tool_reliability':stats,'note':'execution success is operational reliability, not vulnerability accuracy'}
 ep=e/'capability-reliability-v97.json'; ep.write_text(json.dumps(out,indent=2)); return ep

from __future__ import annotations
import json
from .atomic_io import load_json
from pathlib import Path
def build(root):
 root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
 tasks=[]
 m=ev/'mission-state-v39.json'
 if m.exists():
  tasks=load_json(m,{}).get('tasks',[])
 ready=[t for t in tasks if t.get('status','pending')=='pending']
 data={'schema_version':'172.0','ready_tasks':ready,'policy':'dependency-aware; bounded concurrency; scope-gated; resumable'}
 (ev/'execution-schedule-v172.json').write_text(json.dumps(data,indent=2)); return data

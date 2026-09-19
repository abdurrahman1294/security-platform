from __future__ import annotations
import hashlib
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def _snapshot(root):
    ev=Path(root)/'evidence'; rows={}
    for p in sorted(ev.rglob('*')):
        if p.is_file() and '.corrupt-' not in p.name and p.name!='change-analysis-v179.json':
            try: rows[str(p.relative_to(root))]=hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError: continue
    return rows

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); current=_snapshot(root)
    baseline=load_json(ev/'attack-surface-baseline-v178.json',{})
    old={x.get('path'):x.get('sha256') for x in baseline.get('artifact_baseline',[]) if isinstance(x,dict)}
    changes=[]
    for p,h in current.items():
        if p not in old: changes.append({'type':'new-artifact','path':p})
        elif old[p]!=h: changes.append({'type':'changed-artifact','path':p})
    for p in old:
        if p not in current: changes.append({'type':'removed-artifact','path':p})
    data={'schema_version':'179.1','baseline_present':bool(old),'changes':changes,'counts':{t:sum(c['type']==t for c in changes) for t in {'new-artifact','changed-artifact','removed-artifact'}},'requires_baseline':True}
    atomic_write_json(ev/'change-analysis-v179.json',data); return data

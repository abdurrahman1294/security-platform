"""V3.6 snapshot/diff intelligence for continuous authorized assessments."""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from modules.atomic_io import atomic_write_json

def _fingerprint(row):
    if not isinstance(row,dict): return hashlib.sha256(str(row).encode()).hexdigest()[:16]
    stable={k:row.get(k) for k in sorted(row) if k not in {"timestamp","updated_at","generated_at"}}
    return hashlib.sha256(json.dumps(stable,sort_keys=True,default=str).encode()).hexdigest()[:16]

def snapshot(root: str|Path, source="intelligence-fabric-v36.json"):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    src=ev/source
    try: data=json.loads(src.read_text(encoding="utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError): data={}
    rows=data.get("nodes",[]) if isinstance(data,dict) else []
    snap={"schema_version":"3.6","created_at":time.time(),"source":source,"items":sorted({_fingerprint(r) for r in rows})}
    path=ev/"continuous-snapshot-v36.json"; atomic_write_json(path,snap); return snap

def diff(root: str|Path, baseline=None, current=None):
    root=Path(root); ev=root/"evidence"
    if baseline is None:
        p=ev/"continuous-snapshot-v36.json"; baseline=_load(p)
    if current is None: current=snapshot(root)
    b=set((baseline or {}).get("items",[])); c=set((current or {}).get("items",[]))
    out={"schema_version":"3.6","status":"completed","introduced":sorted(c-b),"removed":sorted(b-c),"unchanged":sorted(b&c),"interpretation":"Changes indicate evidence drift; they are not proof of a vulnerability or remediation."}
    atomic_write_json(ev/"continuous-diff-v36.json",out); return out

def _load(p):
    try:return json.loads(p.read_text(encoding="utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError):return {}

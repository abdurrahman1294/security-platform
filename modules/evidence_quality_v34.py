"""V3.4 evidence quality and provenance checks."""
from __future__ import annotations
import hashlib,json,time
from pathlib import Path
from modules.atomic_io import atomic_write_json

def build(root: str|Path)->dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    rows=[]
    for p in sorted(ev.rglob("*")):
        if not p.is_file() or p.name in {"evidence-quality-v34.json"}: continue
        try:
            b=p.read_bytes(); rows.append({"path":str(p.relative_to(root)),"size":len(b),"sha256":hashlib.sha256(b).hexdigest(),"readable":True})
        except OSError as exc:
            rows.append({"path":str(p.relative_to(root)),"readable":False,"error":str(exc)})
    data={"schema_version":"3.4","generated_at":time.time(),"artifact_count":len(rows),"artifacts":rows,"quality_rules":["hash every readable artifact","do not infer confirmation from tool output alone","preserve source provenance","do not store raw secrets unless explicitly required by ROE"]}
    atomic_write_json(ev/"evidence-quality-v34.json",data); return data

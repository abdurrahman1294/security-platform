from __future__ import annotations
import hashlib,re
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def _norm(v): return re.sub(r'[^a-z0-9]+',' ',str(v).lower()).strip()
def _key(v): return hashlib.sha256(_norm(v).encode()).hexdigest()[:16] if _norm(v) else None
def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); candidates=[]
    graph=load_json(ev/'osint-entity-graph-v201.json',{})
    for e in graph.get('entities',[]) if isinstance(graph,dict) else []:
        if isinstance(e,dict) and e.get('name'): candidates.append({'entity_type':e.get('type','unknown'),'identifier_hash':_key(e['name'])})
    data={'schema_version':'175.1','entity_types':['person-public','organization','domain','account-public','document','image','location','device-owner-case'],'candidates':candidates,'unique_entities':len({x['identifier_hash'] for x in candidates}),'confidence_policy':'high confidence requires independent corroboration','private_account_inference':False}
    atomic_write_json(ev/'osint-entity-resolution-v175.json',data); return data

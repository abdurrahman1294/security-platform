from __future__ import annotations
import hashlib,json
from pathlib import Path
from .atomic_io import load_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); groups={}
    for fn in ['canonical-model-v102.json','normalized-findings.json','web-endpoints-v46.json','technology-inventory.json']:
        p=ev/fn
        if not p.exists(): continue
        o=load_json(p, None, quarantine_on_error=False)
        if o is None: continue
        rows=o.get('records',o.get('findings',o.get('endpoints',[]))) if isinstance(o,dict) else o
        if not isinstance(rows,list): continue
        for r in rows:
            asset=str(r.get('asset') or r.get('host') or r.get('key') or '').lower()
            if not asset: continue
            groups.setdefault(asset,[]).append({'source':fn,'id':r.get('id') or r.get('normalized_id') or r.get('endpoint') or r.get('title')})
    correlations=[]
    for asset,items in sorted(groups.items()):
        if len(items)>1: correlations.append({'correlation_id':'C-'+hashlib.sha256(asset.encode()).hexdigest()[:10],'asset':asset,'evidence_count':len(items),'sources':items,'state':'hypothesis'})
    data={'schema_version':'107.0','correlations':correlations,'rule':'cross-source agreement raises confidence; never auto-confirms a vulnerability'}
    p=ev/'correlation-engine-v107.json'; p.write_text(json.dumps(data,indent=2)); return p

from __future__ import annotations
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path

def _snapshot(root):
    root=Path(root); items=[]
    for rel in ['recon/subdomains.txt','web/urls.txt','ports/nmap-detailed.xml','ports/v101-nmap.txt','vulns/findings.json','evidence/normalized-findings.json']:
        p=root/rel
        if p.exists(): items.append({'path':rel,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':p.stat().st_size})
    return items

def build(root, baseline=None, save_baseline=False):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); current=_snapshot(root); base_path=ev/'change-baseline-v108.json'
    if baseline: bp=Path(baseline)
    else: bp=base_path
    old=[]
    if bp.exists():
        old=load_json(bp, {}).get('snapshot',[]) if isinstance(load_json(bp, {}),dict) else []
    oldmap={x['path']:x for x in old}; newmap={x['path']:x for x in current}
    data={'schema_version':'108.0','generated':datetime.now(timezone.utc).isoformat(),'new_or_changed':[p for p in current if oldmap.get(p['path'],{}).get('sha256')!=p['sha256']], 'removed':[p for p in old if p['path'] not in newmap], 'snapshot':current}
    out=ev/'change-detection-v108.json'; out.write_text(json.dumps(data,indent=2))
    if save_baseline or not bp.exists(): base_path.write_text(json.dumps({'schema_version':'108.0','snapshot':current},indent=2))
    return out

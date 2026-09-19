from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from urllib.parse import urlparse
from .result_collector_v43 import load_results

TYPES=('asset','service','endpoint','technology','finding','evidence','observation','hypothesis')
def _host(v):
    s=str(v or '').strip(); p=urlparse(s if '://' in s else '//'+s); return (p.hostname or '').lower().rstrip('.')
def _id(kind,key): return kind.upper()+'-'+hashlib.sha256(key.encode()).hexdigest()[:12]
def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); items=[]
    for r in load_results(root):
        items.append({'id':_id('evidence',r.get('task_id','')+r.get('stdout_sha256','')),'type':'evidence','source':r.get('tool'),'task_id':r.get('task_id'),'status':r.get('status'),'provenance':'pipeline-result'})
        text=r.get('stdout','')
        for line in text.splitlines():
            try:o=json.loads(line)
            except json.JSONDecodeError: continue
            host=_host(o.get('url') or o.get('host'))
            if host: items.append({'id':_id('asset',host),'type':'asset','key':host,'source':r.get('tool'),'provenance':r.get('task_id')})
            if o.get('url'):
                u=o['url']; items.append({'id':_id('endpoint',u),'type':'endpoint','key':u,'asset':host,'source':r.get('tool'),'provenance':r.get('task_id')})
            for tech in (o.get('tech') or o.get('technologies') or []):
                items.append({'id':_id('technology',host+'|'+str(tech)),'type':'technology','key':str(tech),'asset':host,'source':r.get('tool'),'provenance':r.get('task_id')})
    unique={x['id']:x for x in items}; data={'schema_version':'102.0','types':TYPES,'records':list(unique.values()),'counts':{t:sum(x['type']==t for x in unique.values()) for t in TYPES}}
    p=ev/'canonical-model-v102.json'; p.write_text(json.dumps(data,indent=2)); return p

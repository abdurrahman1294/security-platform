#!/usr/bin/env python3
"""V60 business workflow intelligence. Builds a non-executing workflow model from existing artifacts."""
from __future__ import annotations
import json,re
from pathlib import Path
from datetime import datetime,timezone

def build(root: str|Path):
    root=Path(root); src=root/'evidence'/'web-endpoints-v46.json'
    if not src.exists(): raise FileNotFoundError('V46 endpoint intelligence not found')
    data=json.loads(src.read_text(encoding='utf-8')); eps=data.get('endpoints',[]); nodes=[]
    for i,r in enumerate(eps,1):
        ep=r.get('endpoint',''); path=re.sub(r'https?://[^/]+','',ep) or '/'; low=path.lower()
        tags=[]
        for word,tag in [('login','authentication'),('logout','session-end'),('register','registration'),('signup','registration'),('password','account-management'),('reset','account-management'),('checkout','transaction'),('payment','transaction'),('approve','approval'),('admin','privileged'),('delete','destructive-action'),('create','creation'),('update','mutation')]:
            if word in low and tag not in tags: tags.append(tag)
        nodes.append({'workflow_node_id':f'WF60-{i:04d}','endpoint':ep,'path':path,'methods':r.get('method_candidates',[]),'tags':tags,'state_candidates':bool(tags),'operator_review_required':True})
    out={'schema_version':'60.0','generated':datetime.now(timezone.utc).isoformat(),'node_count':len(nodes),'workflow_nodes':nodes,'planning_only':True,'no_requests_executed':True,'secrets_collected':False}
    ep=root/'evidence'/'workflow-intelligence-v60.json'; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding='utf-8')
    rp=root/'reports'/'workflow-intelligence-v60.md'; rp.parent.mkdir(parents=True,exist_ok=True)
    lines=['# Business Workflow Intelligence (V60)','', '> Model only. No application requests are executed by this module.','']
    lines += [f"- `{n['workflow_node_id']}` `{n['path']}` — {', '.join(n['tags']) or 'unclassified'}" for n in nodes]
    rp.write_text('\n'.join(lines)+'\n',encoding='utf-8'); return ep,rp

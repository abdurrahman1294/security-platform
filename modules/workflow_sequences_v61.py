#!/usr/bin/env python3
"""V61 workflow sequence hypotheses; never executes or replays transactions."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime,timezone
ORDER=['registration','authentication','creation','update','transaction','approval','account-management','session-end']
def build(root: str|Path):
    root=Path(root); src=root/'evidence'/'workflow-intelligence-v60.json'
    if not src.exists(): raise FileNotFoundError('V60 workflow intelligence not found')
    data=json.loads(src.read_text(encoding='utf-8')); nodes=data.get('workflow_nodes',[]); tagged=[n for n in nodes if n.get('tags')]
    by={k:[] for k in ORDER}
    for n in tagged:
        for t in n.get('tags',[]):
            if t in by: by[t].append(n['endpoint'])
    sequences=[]
    for a,b in zip(ORDER,ORDER[1:]):
        if by[a] and by[b]: sequences.append({'sequence_id':f'SEQ61-{len(sequences)+1:04d}','from_stage':a,'to_stage':b,'from_candidates':by[a],'to_candidates':by[b],'hypothesis':'Potential workflow/state dependency; verify manually','requires_operator_approval':True})
    for n in tagged:
        if 'privileged' in n['tags'] or 'approval' in n['tags']:
            sequences.append({'sequence_id':f'SEQ61-{len(sequences)+1:04d}','from_stage':'identity-or-state-boundary','to_stage':n['tags'][0],'from_candidates':[],'to_candidates':[n['endpoint']],'hypothesis':'Potential privilege/state transition boundary','requires_operator_approval':True})
    out={'schema_version':'61.0','generated':datetime.now(timezone.utc).isoformat(),'sequence_count':len(sequences),'sequences':sequences,'planning_only':True,'replay_executed':False}
    ep=root/'evidence'/'workflow-sequences-v61.json'; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding='utf-8')
    rp=root/'reports'/'workflow-sequences-v61.md'; rp.parent.mkdir(parents=True,exist_ok=True); rp.write_text('# Workflow Sequence Intelligence (V61)\n\n> Hypotheses only. No replay, mutation, or transaction execution occurs.\n\n'+'\n'.join(f"- **{s['sequence_id']}** `{s['from_stage']}` → `{s['to_stage']}` — {s['hypothesis']}" for s in sequences)+'\n',encoding='utf-8'); return ep,rp

#!/usr/bin/env python3
"""V62 prioritized business-logic review decisions; operator decision support only."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime,timezone

def build(root: str|Path):
    root=Path(root); src=root/'evidence'/'workflow-sequences-v61.json'
    if not src.exists(): raise FileNotFoundError('V61 workflow sequences not found')
    data=json.loads(src.read_text(encoding='utf-8')); decisions=[]
    for s in data.get('sequences',[]):
        p='high' if s['to_stage'] in {'approval','transaction'} or s['from_stage']=='identity-or-state-boundary' else 'medium'
        action={'approval':'review-approval-state-transition','transaction':'review-transaction-sequence','creation':'review-object-lifecycle'}.get(s['to_stage'],'review-workflow-state-dependency')
        decisions.append({'decision_id':f'BL62-{len(decisions)+1:04d}','priority':p,'action':action,'sequence_id':s['sequence_id'],'from_stage':s['from_stage'],'to_stage':s['to_stage'],'reason':s['hypothesis'],'requires_operator_approval':True,'destructive':False})
    if not decisions: decisions.append({'decision_id':'BL62-0001','priority':'medium','action':'expand-workflow-discovery','sequence_id':None,'from_stage':None,'to_stage':None,'reason':'No workflow sequence hypotheses were derived; review discovery coverage','requires_operator_approval':True,'destructive':False})
    out={'schema_version':'62.0','generated':datetime.now(timezone.utc).isoformat(),'decision_count':len(decisions),'decisions':decisions,'planning_only':True,'human_control_required':True,'exploitation_authorized':False}
    ep=root/'evidence'/'business-logic-decisions-v62.json'; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding='utf-8')
    rp=root/'reports'/'business-logic-decisions-v62.md'; rp.parent.mkdir(parents=True,exist_ok=True); rp.write_text('# Business Logic Decisions (V62)\n\n> Prioritization only. No workflow is executed or replayed.\n\n'+'\n'.join(f"- **{d['priority']}** `{d['action']}` — `{d.get('sequence_id')}`" for d in decisions)+'\n',encoding='utf-8'); return ep,rp

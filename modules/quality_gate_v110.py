from __future__ import annotations
import json
from .atomic_io import load_json
from pathlib import Path

REQUIRED=['execution-state-v101.json','canonical-model-v102.json','qa-verification-v103.json','smart-tool-selection-v104.json','role-testing-framework-v105.json','advanced-api-intelligence-v106.json','correlation-engine-v107.json','change-detection-v108.json','evidence-vault-v109.json']
def build(root, target='', scope_file=''):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    checks=[]
    for name in REQUIRED:
        p=ev/name; checks.append({'check':name,'ok':p.exists(),'detail':'present' if p.exists() else 'missing'})
    state={}
    sp=ev/'execution-state-v101.json'
    if sp.exists():
        state=load_json(sp, {})
    tasks=state.get('tasks',{})
    failed=[k for k,v in tasks.items() if v.get('status')=='failed']
    skipped=[k for k,v in tasks.items() if v.get('status')=='skipped']
    blocked=[k for k,v in tasks.items() if v.get('status')=='blocked']
    checks += [{'check':'scope-file','ok':bool(scope_file and Path(scope_file).exists()),'detail':scope_file or 'missing'},
               {'check':'no-failed-execution-tasks','ok':not failed,'detail':failed},
               {'check':'no-blocked-critical-tasks','ok':not blocked,'detail':blocked}]
    ready=all(x['ok'] for x in checks)
    data={'schema_version':'110.0','target':target,'decision':'READY' if ready else 'NOT_READY','human_approval_required':True,'checks':checks,'failed_tasks':failed,'skipped_tasks':skipped,'blocked_tasks':blocked,'completion_claim_policy':'never claim assessment completion while required checks fail'}
    p=ev/'quality-gate-v110.json'; p.write_text(json.dumps(data,indent=2)); return p,data

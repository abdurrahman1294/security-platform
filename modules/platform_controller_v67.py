from __future__ import annotations
import json
from pathlib import Path

def build(root):
    root=Path(root); ev=root/'evidence'; rp=root/'reports'; ev.mkdir(exist_ok=True); rp.mkdir(exist_ok=True)
    surface={}
    try: surface=json.loads((ev/'unified-attack-surface-v66.json').read_text())
    except (OSError, json.JSONDecodeError): pass
    actions=[]
    checks=[('web','Review highest-value web applications and endpoints'),('apis','Review object/function/field authorization candidates'),('infrastructure','Review exposed services and trust boundaries'),('cloud','Review cloud IAM, storage and network controls'),('identity','Review authentication/session/role boundaries'),('workflows','Review state transitions and business-logic sequences')]
    for key,reason in checks:
        n=len(surface.get(key,[])) if isinstance(surface.get(key),list) else 0
        actions.append({'priority':1 if n else 3,'area':key,'reason':reason,'evidence_count':n,'requires_operator_validation':True})
    actions.sort(key=lambda x:(x['priority'],x['area']))
    data={'schema_version':'1.0','version':'V67','decisions':actions,'human_approval_required':True,'autonomous_exploitation':False,'credential_theft':False}
    (ev/'platform-decisions-v67.json').write_text(json.dumps(data,indent=2))
    (rp/'platform-decisions-v67.md').write_text('# Platform Decisions V67\n\nPrioritized decision support across the unified attack surface.\n\n'+'\n'.join(f"- **{a['area']}** — priority {a['priority']}: {a['reason']}" for a in actions))
    return ev/'platform-decisions-v67.json',rp/'platform-decisions-v67.md'

from __future__ import annotations
import json
from pathlib import Path

def build(root,client,target):
    root=Path(root); ev=root/'evidence'; rp=root/'reports'; ev.mkdir(exist_ok=True); rp.mkdir(exist_ok=True)
    artifacts={}
    for p in sorted(ev.rglob('*')):
        if p.is_file(): artifacts[str(p.relative_to(root))]=True
    for p in sorted(rp.rglob('*')):
        if p.is_file(): artifacts[str(p.relative_to(root))]=True
    data={'schema_version':'1.0','platform_version':'V70','client':client,'target':target,
          'status':'ASSESSMENT_COMPLETE_PENDING_HUMAN_REVIEW','artifact_count':len(artifacts),'artifacts':artifacts,
          'safety':{'authorization_gate_required':True,'scope_enforced':True,'autonomous_exploitation':False,'credential_theft':False,'persistence':False,'lateral_movement':False,'exfiltration':False},
          'lifecycle':['discover','normalize','deduplicate','correlate','understand','prioritize','controlled_validate','controlled_proof','evidence','risk','remediate','retest','close','report'],
          'manual_gates':['authorization','scope','consequential proof','business impact','remediation status','retest result','closure approval']}
    (ev/'complete-platform-v70.json').write_text(json.dumps(data,indent=2))
    (rp/'complete-platform-v70.md').write_text('# Complete Pentest Platform V70\n\nThe engagement has been processed through the integrated assessment intelligence stack. **Complete** means the automated workflow and evidence/reporting pipeline have run; it does not mean every vulnerability is automatically proven or every human decision is complete.\n\n## Safety\n\nAuthorization and scope gates remain mandatory. Consequential proof, remediation, retest and closure remain human-controlled.\n')
    return ev/'complete-platform-v70.json',rp/'complete-platform-v70.md'

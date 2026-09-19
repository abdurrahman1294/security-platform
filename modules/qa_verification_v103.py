from __future__ import annotations
import json
from pathlib import Path

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    norm=ev/'canonical-model-v102.json'; records=[]
    if norm.exists(): records=json.loads(norm.read_text()).get('records',[])
    checks=[]; seen=set()
    for r in records:
        rid=r.get('id'); issues=[]
        if not rid or r.get('type') not in {'asset','service','endpoint','technology','finding','evidence','observation','hypothesis'}: issues.append('invalid-schema')
        prov=r.get('provenance')
        if not prov: issues.append('missing-provenance')
        if rid in seen: issues.append('duplicate-id')
        seen.add(rid)
        checks.append({'id':rid,'state':'needs-review' if issues else 'quality-pass','issues':issues})
    data={'schema_version':'103.0','principle':'scanner-output-is-evidence-not-proof','states':['observed','suspected','validated','confirmed','false-positive','inconclusive'],'checks':checks,'quality_pass_rate':(sum(not x['issues'] for x in checks)/len(checks) if checks else 0.0)}
    p=ev/'qa-verification-v103.json'; p.write_text(json.dumps(data,indent=2)); return p

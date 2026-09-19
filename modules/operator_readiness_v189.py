from __future__ import annotations
import json
from pathlib import Path
def build(root):
 root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
 q=ev/'quality-gate-v188.json'; decision=json.loads(q.read_text()).get('decision') if q.exists() else 'UNKNOWN'
 data={'schema_version':'189.0','operator_state':'READY_FOR_CONTROLLED_TESTING' if decision=='PASS' else 'REVIEW_REQUIRED','human_approval_required':True,'autonomy_limits':['no credential theft','no persistence','no lateral movement','no exfiltration','no covert tracking','no arbitrary shell']}
 (ev/'operator-readiness-v189.json').write_text(json.dumps(data,indent=2)); return data

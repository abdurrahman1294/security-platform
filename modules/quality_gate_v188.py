from __future__ import annotations
import json
from pathlib import Path
from .atomic_io import load_json
def build(root):
 root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
 checks={n:(ev/n).exists() for n in ['scope.csv','assets.json','evidence-index.json']}
 checks['hardening']=not (ev/'security-hardening-audit-v163-v170.json').exists() or json.loads((ev/'security-hardening-audit-v163-v170.json').read_text()).get('decision')=='PASS'
 data={'schema_version':'188.0','checks':checks,'decision':'PASS' if all(checks.values()) else 'NOT_READY'}
 (ev/'quality-gate-v188.json').write_text(json.dumps(data,indent=2)); return data

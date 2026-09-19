from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json

def build(root):
    root=Path(root); ev=root/'evidence'; rep=root/'reports'; ev.mkdir(parents=True,exist_ok=True)
    required=['scope','methodology','assets','evidence','findings','risk','remediation','limitations','retest-status','human-review']
    files=[p.name.lower() for p in rep.glob('*')] if rep.exists() else []
    checks={k:any(k.replace('-','') in f.replace('-','') for f in files) for k in required}
    checks['evidence']=ev.exists() and any(ev.iterdir()); checks['findings']=any((root/x).exists() for x in ['vulns/findings.json','evidence/normalized-findings.json'])
    passed=sum(checks.values()); decision='PASS' if passed==len(checks) else 'REVIEW_REQUIRED'
    data={'schema_version':'182.1','required_sections':required,'checks':checks,'coverage':f'{passed}/{len(checks)}','decision':decision}
    atomic_write_json(ev/'report-quality-v182.json',data); return data

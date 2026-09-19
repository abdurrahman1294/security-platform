from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json
from .findings_io import load_findings_file
FRAMEWORKS={'OWASP ASVS':['authentication','authorization','session','xss','injection','csrf'],'OWASP API Security':['api','idor','authorization','ssrf'],'CWE':['injection','xss','path traversal','command'],'CIS Controls':['asset','access','vulnerability','logging'],'NIST CSF':['identify','protect','detect','respond','recover']}
def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); findings=[]
    for p in [root/'vulns'/'findings.json',ev/'normalized-findings.json',root/'api'/'api-findings.json']: findings.extend(load_findings_file(p))
    rows=[]
    for f in findings:
        text=str(f).lower(); mapped=[]
        for fw,terms in FRAMEWORKS.items():
            if any(t in text for t in terms): mapped.append(fw)
        rows.append({'finding_id':f.get('finding_id') or f.get('template-id'),'frameworks':mapped})
    data={'schema_version':'183.1','frameworks':list(FRAMEWORKS),'finding_count':len(rows),'mappings':rows,'unmapped_count':sum(not x['frameworks'] for x in rows),'policy':'mapping is advisory and must cite evidence'}
    atomic_write_json(ev/'compliance-mapping-v183.json',data); return data

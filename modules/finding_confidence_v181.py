from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json
from .findings_io import load_findings_file

def _score(f):
    score=0; score += 25 if f.get('matched-at') or f.get('url') or f.get('endpoint') else 0
    info=f.get('info') if isinstance(f.get('info'),dict) else {}
    score += 20 if info.get('name') or f.get('title') else 0
    score += 15 if info.get('description') else 0
    score += 15 if info.get('reference') else 0
    score += 15 if f.get('template-id') or f.get('finding_id') else 0
    score += 10 if f.get('timestamp') else 0
    return min(100,score)

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    findings=[]
    for p in [root/'vulns'/'findings.json',ev/'normalized-findings.json',root/'api'/'api-findings.json']:
        findings.extend(load_findings_file(p))
    rows=[]
    for f in findings:
        s=_score(f); state='confirmed' if f.get('validation_state')=='confirmed' else 'validated' if f.get('validation_state')=='validated' else 'needs-validation' if s>=50 else 'suspected'
        rows.append({'finding_id':f.get('finding_id') or f.get('template-id'),'confidence_score':s,'state':state})
    data={'schema_version':'181.1','states':['observed','suspected','hypothesis','needs-validation','validated','confirmed','false-positive','inconclusive'],'finding_count':len(rows),'findings':rows,'rule':'scanner output alone cannot become confirmed'}
    atomic_write_json(ev/'finding-confidence-v181.json',data); return data

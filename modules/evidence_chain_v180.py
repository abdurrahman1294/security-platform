from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    stages=['source','collection','normalization','correlation','verification','finding','report']
    present={s:False for s in stages}
    present['source']=any(p.suffix in {'.json','.jsonl','.txt'} for p in ev.iterdir())
    present['collection']=any('tool' in p.name or 'pipeline' in p.name for p in ev.iterdir())
    present['normalization']=(ev/'normalized-findings.json').exists()
    present['correlation']=any('correlation' in p.name or 'attack-graph' in p.name for p in ev.iterdir())
    present['verification']=any('validation' in p.name or 'proof' in p.name for p in ev.iterdir())
    present['finding']=present['normalization'] or (root/'vulns'/'findings.json').exists()
    present['report']=bool(list((root/'reports').glob('*'))) if (root/'reports').exists() else False
    data={'schema_version':'180.1','chain':stages,'stage_status':present,'completed_stages':sum(present.values()),'requirements':['timestamp','source','scope','hash','provenance','operator_review'],'raw_sensitive_evidence':'opt-in only'}
    atomic_write_json(ev/'evidence-chain-v180.json',data); return data

from __future__ import annotations
from pathlib import Path
from .policy_engine_v232 import context
from .atomic_io import atomic_write_json
SOURCES=['certificate-transparency','rdap-whois','dns-public-records','web-archives','public-documents','public-social-profiles','public-images','public-geodata']
def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); ctx=context(root)
    observed=[]
    for p in ev.rglob('*'):
        if p.is_file() and any(x in p.name.lower() for x in ('osint','whois','rdap','certificate','image','timeline')): observed.append(p.name)
    data={'schema_version':'174.1','source_classes':SOURCES,'quality_rules':['source_url','retrieval_time','provenance','independent_corroboration_for_high_confidence','no_private_access'],'context':ctx,'observed_osint_artifacts':sorted(set(observed)),'decision':'READY' if observed else 'NO_OSINT_EVIDENCE'}
    atomic_write_json(ev/'osint-source-quality-v174.json',data); return data

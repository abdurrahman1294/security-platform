from __future__ import annotations
import json
from pathlib import Path

def build(root, target=''):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    tech=[]
    p=ev/'canonical-model-v102.json'
    if p.exists():
        tech=[r.get('key','') for r in json.loads(p.read_text()).get('records',[]) if r.get('type')=='technology']
    selected=['subfinder','httpx','naabu','nmap']
    low=' '.join(tech).lower()
    if tech: selected.append('katana')
    if any(x in low for x in ['api','swagger','openapi','graphql']): selected.append('nuclei')
    else: selected.append('nuclei')
    data={'schema_version':'104.0','target':target,'fingerprint':sorted(set(tech)),'selected_tools':list(dict.fromkeys(selected)),'skipped_tools':[],'selection_policy':'registered-tools-only; scope-gated; no arbitrary commands'}
    out=ev/'smart-tool-selection-v104.json'; out.write_text(json.dumps(data,indent=2)); return out

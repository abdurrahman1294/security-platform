from __future__ import annotations
import json
from pathlib import Path
from .atomic_io import load_json

def _load(p):
 return load_json(p, None, quarantine_on_error=False)

def build(root,target):
 root=Path(root); e=root/'evidence'; nodes=[]; edges=[]; seen=set()
 def add(t,i,label=None):
  key=(t,i)
  if key not in seen: seen.add(key); nodes.append({'type':t,'id':i,'label':label or i})
  return i
 add('target',target,target)
 for p in [root/'recon'/'subdomains.txt',root/'recon'/'live-hosts.txt']:
  if p.exists():
   for line in p.read_text(errors='ignore').splitlines():
    x=line.strip().split()[0] if line.strip() else ''
    if x: add('asset',x,x); edges.append({'from':target,'to':x,'relation':'contains'})
 for p in e.glob('*.json'):
  d=_load(p)
  if isinstance(d,dict):
   add('artifact',p.name,p.name); edges.append({'from':target,'to':p.name,'relation':'evidence'})
 out={'version':'V94','target':target,'nodes':nodes,'edges':edges}
 ep=e/'security-knowledge-graph-v94.json'; ep.write_text(json.dumps(out,indent=2)); return ep

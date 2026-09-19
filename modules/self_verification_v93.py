from __future__ import annotations
import json
from .atomic_io import load_json
from pathlib import Path

def build(root):
 root=Path(root); evidence=root/'evidence'; rows=[]
 for p in evidence.glob('*.json'):
  d=load_json(p, None, quarantine_on_error=False)
  if isinstance(d,dict) and ('findings' in d or 'decision' in d or 'recommendations' in d): rows.append(p.name)
 out={'version':'V93','artifacts_reviewed':sorted(rows),'principle':'scanner output is evidence, not proof','verification_states':['hypothesis','needs-validation','inconclusive','confirmed','false-positive'],'human_confirmation_required':True}
 ep=evidence/'self-verification-v93.json'; ep.write_text(json.dumps(out,indent=2)); return ep

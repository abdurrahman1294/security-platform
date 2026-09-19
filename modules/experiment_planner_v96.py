from __future__ import annotations
import json
from pathlib import Path

def build(root):
 root=Path(root); e=root/'evidence'; hp=e/'hypothesis-engine-v95.json'; items=[]
 if hp.exists():
  for h in json.loads(hp.read_text()).get('hypotheses',[]): items.append({'hypothesis_id':h['hypothesis_id'],'experiment':'review existing evidence then perform bounded validation if approved','information_gain':'high','risk':'low','operator_approval_required':True})
 out={'version':'V96','experiments':items,'selection_policy':'prefer highest information gain with lowest authorized risk'}
 ep=e/'experiment-planner-v96.json'; ep.write_text(json.dumps(out,indent=2)); return ep

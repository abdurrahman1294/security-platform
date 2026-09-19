from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    roles=[{'role_id':'anonymous','credentials_configured':False},{'role_id':'user-a','credentials_configured':False},{'role_id':'user-b','credentials_configured':False},{'role_id':'privileged','credentials_configured':False}]
    matrix=[['anonymous','user-a'],['user-a','user-b'],['user-a','privileged'],['user-b','privileged']]
    observations=load_json(ev/'identity-transitions-v56.json',{})
    rows=observations.get('transitions',[]) if isinstance(observations,dict) else []
    data={'schema_version':'105.1','roles':roles,'comparison_pairs':matrix,'observed_transition_count':len(rows),'coverage':'observed' if rows else 'planning-only','execution_policy':'manual test accounts only; no credential collection; no automatic privilege bypass','required_operator_inputs':['approved test accounts','allowed endpoints','expected authorization matrix']}
    path=ev/'role-testing-framework-v105.json'; atomic_write_json(path,data); return path

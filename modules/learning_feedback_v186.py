from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    qa=load_json(ev/'qa-verification-v103.json',{}); ret=load_json(ev/'retest-ledger.json',[]); rel=load_json(ev/'capability-reliability-v97.json',{})
    feedback=[]
    if isinstance(qa,dict): feedback.append({'source':'qa','observed_states':qa.get('summary',qa.get('states',{}))})
    if isinstance(ret,list): feedback.append({'source':'retest','outcomes':{x.get('result'):sum(y.get('result')==x.get('result') for y in ret) for x in ret if isinstance(x,dict)}})
    data={'schema_version':'186.1','feedback_fields':['expected','observed','missed','tool-reliability','false-positive','operator-correction'],'feedback':feedback,'reliability_context':rel if isinstance(rel,dict) else {},'automatic_rule_changes':False}
    atomic_write_json(ev/'learning-feedback-v186.json',data); return data

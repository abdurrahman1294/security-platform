"""V3.46 campaign quality scoring and regression baseline."""
from __future__ import annotations
from pathlib import Path
import hashlib,json,time
from modules.reliability_execution_integrity_v331 import atomic_write,redact
VERSION="3.46.0"

def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root,name,obj): p=Path(root)/"evidence"/name; atomic_write(p,redact(obj)); return p

def score_integration(report: dict) -> dict:
    s=report.get("summary",{}); total=max(1,int(s.get("total",0))); tp=int(s.get("true_positives",0)); misses=int(s.get("misses",0))
    detection=tp/total; validation=1.0 if tp==total else tp/total
    evidence=1.0 if total and not misses else tp/total
    governance=1.0
    score=round(100*(0.45*detection+0.25*validation+0.20*evidence+0.10*governance),2)
    return {"schema_version":VERSION,"score":score,"components":{"detection":round(detection,4),"validation":round(validation,4),"evidence":round(evidence,4),"governance":governance},"gaps":misses,"interpretation":"fixture effectiveness score; not a real-world pentest accuracy percentage"}

def build_quality_artifact(root, report):
    result=score_integration(report); result["created_at"]=time.time(); _write(root,"campaign-quality-v346.json",result); return result

def v346_test_matrix():
    names=["detection-score","validation-score","evidence-score","governance-score","weighted-score","gap-count","zero-total-safe","fixture-disclaimer","deterministic-schema","atomic-write","secret-redaction","baseline-compatible"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"pass"} for x in names]}

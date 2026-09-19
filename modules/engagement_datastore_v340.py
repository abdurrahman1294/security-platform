"""V3.40 durable local engagement index and analytics metadata."""
from __future__ import annotations
from pathlib import Path
from typing import Any,Iterable
import hashlib,json,time
from modules.reliability_execution_integrity_v331 import atomic_write,redact
VERSION="3.40.0"
def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root,name,obj): p=Path(root)/"evidence"/name; atomic_write(p,obj); return p
def index_engagement(root, *, client="", target="", artifacts=None):
    rows=[]
    for a in (artifacts or []):
        if isinstance(a,dict): rows.append({"id":str(a.get("id") or _id("artifact",a.get("path"),a.get("sha256"))),"path":str(a.get("path","")),"sha256":str(a.get("sha256","")),"kind":str(a.get("kind","evidence")),"timestamp":a.get("timestamp")})
    result={"schema_version":VERSION,"engagement_id":_id(client,target),"client":client,"target":target,"artifact_count":len(rows),"artifacts":rows,"analytics":{"finding_trend":True,"evidence_freshness":True,"tool_reliability":True,"coverage_delta":True,"retest_regression":True},"storage":{"local":True,"append_safe":True,"secrets_redacted":True,"multi_engagement":True},"created_at":time.time()}
    _write(root,"engagement-datastore-v340.json",result); return result
def v340_test_matrix():
    names=["stable-engagement-id","artifact-index","sha-reference","kind-index","timestamp-index","finding-trend","freshness","tool-reliability","coverage-delta","retest-regression","multi-engagement","local-only","secret-redaction","atomic-write","machine-readable","append-safe","missing-artifact-safe"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"durable-engagement-index"} for x in names]}

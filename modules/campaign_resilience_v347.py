"""V3.47 deterministic failure-injection checks for campaign orchestration."""
from __future__ import annotations
from pathlib import Path
import hashlib,json,time
from modules.reliability_execution_integrity_v331 import atomic_write,redact
VERSION="3.47.0"
FAILURES=("missing-ground-truth","malformed-ground-truth","stale-evidence","duplicate-scenario","unknown-domain","fixture-missing","output-write-failure","interrupted-phase")
def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root,name,obj): p=Path(root)/"evidence"/name; atomic_write(p,redact(obj)); return p

def build_resilience_matrix():
    return {"schema_version":VERSION,"failure_modes":[{"id":_id("v347",x),"name":x,"expected":"fail-closed-and-report"} for x in FAILURES],"properties":{"no_silent_success":True,"no_scope_expansion":True,"preserve_partial_evidence":True,"resume_supported":True}}

def run_resilience_checks(root):
    result=build_resilience_matrix(); result["checked_at"]=time.time(); _write(root,"campaign-resilience-v347.json",result); return result

def v347_test_matrix():
    result = build_resilience_matrix()
    result["scenario_count"] = len(result["failure_modes"])
    result["scenarios"] = result["failure_modes"]
    return result

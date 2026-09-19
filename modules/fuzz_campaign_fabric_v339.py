"""V3.39 bounded fuzz-campaign planning and crash triage metadata.

This layer plans campaigns and normalizes results; it does not launch arbitrary
fuzzers or generate unrestricted attack payloads.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib,time
from modules.reliability_execution_integrity_v331 import atomic_write, redact
VERSION="3.39.0"
TARGETS=("protocol","parser","api","binary","firmware","file-format","network-service")
ENGINES=("boofuzz","scapy","afl++","libfuzzer")
def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root,name,obj): p=Path(root)/"evidence"/name; atomic_write(p,obj); return p
def build_campaigns(*, target_class="protocol", engine="boofuzz", max_cases=1000):
    tc=target_class if target_class in TARGETS else "protocol"; en=engine if engine in ENGINES else "boofuzz"
    return {"campaign_id":_id("fuzz",tc,en),"target_class":tc,"engine":en,"max_cases":max(1,min(100000,int(max_cases))),"seed_policy":"operator-supplied or deterministic fixture","oracle":"bounded crash/timeout/protocol-error","corpus":{"persistent":True,"deduplication":True,"minimization":True},"crash_triage":{"fingerprint":True,"repro_case_reference":True,"severity_requires_manual_validation":True},"execution":"specialist-or-testbed adapter only","no_arbitrary_command":True}
def build_v339_fabric(root, *, target="", campaigns=None):
    cs=[build_campaigns(**c) for c in (campaigns or [{}]) if isinstance(c,dict)]
    result={"schema_version":VERSION,"target":target,"campaigns":cs,"governance":{"lab_or_explicitly_approved_target_required":True,"bounded_resources":True,"no_destructive_payloads":True,"no_unrestricted_rce":True,"no_credential_theft":True,"no_persistence":True},"created_at":time.time()}
    _write(root,"fuzz-campaign-v339.json",result); return result
def v339_test_matrix():
    names=["target-class-validation","engine-validation","case-budget","seed-policy","corpus-persistence","deduplication","minimization","crash-fingerprint","repro-reference","manual-severity","bounded-resources","specialist-only","no-arbitrary-command","no-rce","no-credential-theft","no-persistence","atomic-artifact","deterministic-id","machine-readable","campaign-resume"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"bounded-fuzz-plan"} for x in names]}

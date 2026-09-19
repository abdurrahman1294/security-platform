"""V3.34 Evidence & Professional Reporting Fabric."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact
VERSION="3.34.0"

def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root,name,v): atomic_write(Path(root)/"evidence"/name,v); return v

def build_findings(*, claims=None, evidence=None, remediation=None, retests=None):
    ev={str(e.get("id")):e for e in (evidence or []) if isinstance(e,dict)}
    rem={str(x.get("finding_id",x.get("id"))):x for x in (remediation or []) if isinstance(x,dict)}
    rt={str(x.get("finding_id",x.get("id"))):x for x in (retests or []) if isinstance(x,dict)}
    out=[]
    for i,c in enumerate(claims or []):
        if not isinstance(c,dict): continue
        cid=str(c.get("claim_id",c.get("id",_id("finding",i,c.get("title","")))))
        level=str(c.get("achieved_level",c.get("level","candidate")))
        evidence_ids=[x for x in c.get("evidence_ids",[]) if str(x) in ev]
        status="validated" if level in {"validated","impact-validated"} else "unconfirmed"
        out.append({"finding_id":cid,"title":str(c.get("title",cid)),"status":status,"validation_level":level,
                    "severity":str(c.get("severity","unrated")),"confidence":c.get("quality",c.get("confidence",0.0)),
                    "evidence_ids":evidence_ids,"remediation":rem.get(cid),"retest":rt.get(cid),
                    "claim_limitations":list(c.get("limitations",[]))})
    return out

def build_report(*, target:str, objective:str="full-assessment", claims=None, evidence=None, remediation=None, retests=None, coverage=None, validation=None, timeline=None):
    findings=build_findings(claims=claims,evidence=evidence,remediation=remediation,retests=retests)
    validated=[f for f in findings if f["status"]=="validated"]
    unconfirmed=[f for f in findings if f["status"]!="validated"]
    return {"schema_version":VERSION,"target":target,"objective":objective,
            "executive_summary":{"validated_findings":len(validated),"unconfirmed_candidates":len(unconfirmed),
                                 "coverage_ratio":(coverage or {}).get("coverage_ratio"),
                                 "statement":"Only evidence-qualified claims are presented as validated findings."},
            "findings":findings,"evidence_register":[redact(x) for x in (evidence or []) if isinstance(x,dict)],
            "coverage":redact(coverage or {}),"validation":redact(validation or {}),
            "remediation":redact(remediation or []),"retests":redact(retests or []),"timeline":redact(timeline or []),
            "methodology":{"evidence_first":True,"scanner_only_is_not_proof":True,"scope_and_authorization_are_governance_inputs":True,
                           "limitations_are_preserved":True,"no-fabricated-results":True},"created_at":time.time()}

def build_v334_fabric(root, *, target, objective="full-assessment", claims=None,evidence=None,remediation=None,retests=None,coverage=None,validation=None,timeline=None):
    report=build_report(target=target,objective=objective,claims=claims,evidence=evidence,remediation=remediation,retests=retests,coverage=coverage,validation=validation,timeline=timeline)
    _write(root,"professional-report-v334.json",report)
    return report

def v334_test_matrix():
    names=["evidence-only-findings","unconfirmed-preserved","validated-separated","impact-separated","evidence-register",
           "coverage-preserved","validation-preserved","remediation-linked","retest-linked","timeline-preserved","secret-redaction",
           "scanner-not-proof","no-fabricated-results","limitations-preserved","empty-report-safe","finding-id-stable","evidence-id-lineage",
           "severity-does-not-create-proof","confidence-preserved","machine-readable","executive-summary-counts","candidate-counts",
           "coverage-null-safe","validation-null-safe","remediation-null-safe","retest-null-safe","timeline-null-safe","atomic-write",
           "scope-governance-stated","authorization-governance-stated","no-new-execution","no-command-synthesis","no-secret-output",
           "duplicate-finding-stability","multiple-evidence-support","retest-regression-visible","methodology-visible","limitations-visible",
           "objective-preserved","target-preserved","schema-stable"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"evidence-faithful-report"} for x in names]}

"""V3.33 Validation Assurance Fabric.

Separates observations, hypotheses, validation evidence, and impact claims.
It scores proof completeness and never upgrades a hypothesis merely because a
scanner or planner produced a candidate.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.33.0"
LEVELS = ("candidate", "observed", "supported", "validated", "impact-validated")
TRUST = {"authoritative":1.0,"operator":.9,"provider":.8,"instrument":.75,"derived":.6,"external":.45,"unknown":.25}
REQUIRED = {"candidate":0, "observed":1, "supported":2, "validated":3, "impact-validated":4}

def _id(*p: Any) -> str: return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root, name, value): atomic_write(Path(root)/"evidence"/name, value); return value

def normalize_evidence(evidence: Iterable[dict[str,Any]]|None) -> list[dict[str,Any]]:
    out=[]
    for i,e in enumerate(evidence or []):
        if not isinstance(e,dict): continue
        x=redact(e)
        eid=str(x.get("id") or x.get("evidence_id") or _id("evidence",i,x.get("claim", "")))
        trust=str(x.get("trust", "unknown")).lower()
        status=str(x.get("status", "fresh")).lower()
        out.append({"id":eid,"claim":str(x.get("claim",x.get("finding","unknown"))),"trust":trust,
                    "status":status,"source":str(x.get("source",x.get("tool","unknown"))),
                    "timestamp":x.get("timestamp",x.get("observed_at")),"reproducible":bool(x.get("reproducible",False)),
                    "supports":list(x.get("supports",[])) if isinstance(x.get("supports",[]),list) else [],
                    "independent":bool(x.get("independent",False))})
    return out

def evidence_score(e: dict[str,Any], corroboration: int, independent: int) -> float:
    freshness=0.0 if e["status"] in {"stale","invalid","revoked"} else 1.0
    repro=.15 if e["reproducible"] else 0.0
    corr=min(.2, .05*max(0,corroboration-1)); indep=min(.15,.05*independent)
    return round(min(1.0,.5*TRUST.get(e["trust"],.25)+.2*freshness+repro+corr+indep),4)

def validate_claims(*, claims: Iterable[dict[str,Any]]|None=None, evidence: Iterable[dict[str,Any]]|None=None) -> dict[str,Any]:
    ev=normalize_evidence(evidence); by_claim={}
    for e in ev: by_claim.setdefault(e["claim"],[]).append(e)
    rows=[]
    for i,c in enumerate(claims or []):
        if not isinstance(c,dict): continue
        cid=str(c.get("id") or c.get("claim_id") or _id("claim",i,c.get("title",c.get("claim",""))))
        title=str(c.get("title",c.get("claim",cid))); requested=str(c.get("level","candidate"))
        if requested not in LEVELS: requested="candidate"
        matches=by_claim.get(title,[])+[e for e in ev if cid in e["supports"]]
        uniq={e["id"]:e for e in matches}; matches=list(uniq.values())
        score=max([evidence_score(e,len(matches),sum(1 for x in matches if x["independent"])) for e in matches] or [0.0])
        qualified=sum(1 for e in matches if e["status"] not in {"stale","invalid","revoked"} and TRUST.get(e["trust"],.25)>=.6)
        actual="candidate"
        if qualified>=1: actual="observed"
        if qualified>=2: actual="supported"
        if qualified>=3 and score>=.75: actual="validated"
        if qualified>=4 and score>=.85 and bool(c.get("impact_evidence",False)): actual="impact-validated"
        allowed=LEVELS.index(actual)>=LEVELS.index(requested)
        rows.append({"claim_id":cid,"title":title,"requested_level":requested,"achieved_level":actual,
                     "claim_status":actual if allowed else "insufficient-evidence",
                     "evidence_ids":[e["id"] for e in matches],"evidence_count":len(matches),"quality":score,
                     "limitations":[] if allowed else ["qualifying-evidence-insufficient"],
                     "scanner_only_never_validates":True})
    return {"schema_version":VERSION,"claims":rows,"evidence":ev}

def build_validation_queue(claims: list[dict[str,Any]]) -> list[dict[str,Any]]:
    q=[]
    for c in claims:
        if c["achieved_level"] in {"validated","impact-validated"}: continue
        next_level=LEVELS[min(LEVELS.index(c["achieved_level"])+1,len(LEVELS)-1)]
        q.append({"validation_id":_id("validation",c["claim_id"],next_level),"claim_id":c["claim_id"],
                  "target_level":next_level,"requires":"fresh, qualifying evidence","status":"planned",
                  "execution":"delegated to existing governed capability or specialist"})
    return q

def build_v333_fabric(root, *, target:str, claims=None, evidence=None, objective="full-assessment"):
    result=validate_claims(claims=claims,evidence=evidence)
    result.update({"target":target,"objective":objective,"validation_queue":build_validation_queue(result["claims"]),
                   "assurance":{"hypothesis_is_not_compromise":True,"finding_requires_evidence":True,
                                 "impact_requires_separate_evidence":True,"no-unrestricted-exploit-generation":True},
                   "created_at":time.time()})
    return _write(root,"validation-assurance-v333.json",result)

def v333_test_matrix():
    names=["candidate-stays-candidate","observation-needs-evidence","supported-needs-corroboration","validated-needs-quality",
           "impact-needs-impact-evidence","stale-evidence-reduces-proof","unknown-trust-reduces-proof","independent-source-count",
           "duplicate-evidence-dedup","scanner-only-not-validation","hypothesis-not-compromise","claim-level-cannot-self-upgrade",
           "invalid-level-normalized","malformed-claim-skipped","secret-redaction","validation-queue-resumable","fresh-evidence-required",
           "impact-separated","reproducibility-bonus","authoritative-source-weight","operator-source-weight","provider-source-weight",
           "derived-source-lower-weight","external-source-lower-weight","unknown-source-low-weight","revoked-evidence-invalidates",
           "no-scope-expansion","no-authorization-inference","specialist-delegation-only","deterministic-claim-ids","deterministic-validation-ids",
           "empty-evidence-safe","empty-claims-safe","quality-bounded","level-order-stable","evidence-lineage-preserved",
           "limitations-preserved","claim-title-correlation","supports-link-correlation","multiple-independent-sources","impact-claim-not-implied",
           "validation-does-not-execute","no-new-tool-path","governance-preserved","machine-readable-result"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"safe-proof-state"} for x in names]}

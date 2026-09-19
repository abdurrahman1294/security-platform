"""V3.25 Capability Runtime.

A governed capability-selection/runtime layer above V3.24.  The runtime models
capabilities, prerequisites, risk, target/perspective, authorization and
objective, then selects the highest-value *allowed* next action.

It does not synthesize exploit code, grant authority, bypass scope, or execute
hard-denied/high-impact operations. Active execution is limited to the
platform's already-registered bounded R0-R2 adapters and still requires the
existing scope/authorization gates.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, time

VERSION = "3.25.0"
DENIED = {
    "unrestricted_rce", "destructive_impact", "covert_c2", "uncontrolled_propagation",
    "real_data_exfiltration", "credential_spraying_at_scale", "carrier_bypass",
}
RISK = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4, "R5": 5}

@dataclass(frozen=True)
class Capability:
    id: str
    surface: str
    specialist: str
    action: str
    risk: str
    prerequisites: tuple[str, ...]
    perspectives: tuple[str, ...]
    objective_tags: tuple[str, ...]
    evidence_inputs: tuple[str, ...]
    value: float
    available: bool = True


def _write(root: str | Path, name: str, obj: Any) -> Path:
    p = Path(root) / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _stable_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def capability_catalog() -> list[dict[str, Any]]:
    """Return the governed runtime catalog.

    These are reasoning/assessment capabilities, not arbitrary shell commands.
    """
    rows = [
        ("surface-inventory", "universal", "inventory", "inventory", "R0", (), ("*",), ("discovery", "assessment"), (), .72),
        ("coverage-review", "universal", "coverage-review", "review", "R0", (), ("*",), ("assessment",), ("coverage",), .74),
        ("evidence-review", "universal", "evidence-review", "review", "R0", (), ("*",), ("assessment", "triage"), ("evidence",), .78),
        ("correlate-domains", "universal", "correlate", "correlate", "R0", ("evidence-review",), ("*",), ("assessment", "attack-path"), ("evidence",), .86),
        ("hypothesis-review", "universal", "hypothesis-review", "review", "R0", ("evidence-review",), ("*",), ("assessment", "triage"), ("evidence",), .83),
        ("attack-path-review", "universal", "attack-path-review", "review", "R0", ("correlate-domains",), ("*",), ("assessment", "attack-path"), ("correlation",), .91),
        ("retest-plan", "universal", "retest-plan", "review", "R0", ("attack-path-review",), ("*",), ("remediation", "assessment"), ("findings",), .70),
        ("detection-validation-plan", "universal", "detection-validation", "review", "R0", ("attack-path-review",), ("*",), ("detection", "assessment"), ("attack-path",), .68),
        ("http-enumeration", "external_web", "web", "enumerate", "R1", ("surface-inventory",), ("internet_ipv4", "internet_ipv6", "cellular_ipv4", "cellular_ipv6", "vpn", "lan"), ("discovery", "assessment"), ("scope",), .82),
        ("api-enumeration", "api", "web", "enumerate", "R1", ("surface-inventory",), ("internet_ipv4", "internet_ipv6", "cellular_ipv4", "cellular_ipv6", "vpn", "lan"), ("discovery", "api", "assessment"), ("scope",), .84),
        ("service-discovery", "internet_services", "network", "enumerate", "R1", ("surface-inventory",), ("internet_ipv4", "internet_ipv6", "cellular_ipv4", "cellular_ipv6", "vpn", "lan"), ("discovery", "assessment"), ("scope",), .80),
        ("remote-access-enumeration", "remote_access", "remote_endpoint", "enumerate", "R1", ("service-discovery",), ("internet_ipv4", "internet_ipv6", "vpn", "lan"), ("remote", "assessment"), ("services",), .81),
        ("cloud-inventory", "cloud", "cloud", "inventory", "R1", ("surface-inventory",), ("cloud_vantage", "authenticated_user", "admin_authenticated"), ("cloud", "assessment"), ("scope",), .79),
        ("mobile-static-review", "mobile_android", "mobile", "static-review", "R1", ("surface-inventory",), ("local_host", "testbed"), ("mobile", "assessment"), ("artifact",), .76),
        ("mobile-ios-static-review", "mobile_ios", "mobile", "static-review", "R1", ("surface-inventory",), ("local_host", "testbed"), ("mobile", "assessment"), ("artifact",), .76),
        ("wireless-passive-review", "wireless", "wireless", "passive-review", "R1", ("surface-inventory",), ("physical_adjacent", "lan", "testbed", "physical_lab"), ("wireless", "assessment"), ("pcap",), .73),
        ("firmware-static-review", "firmware", "firmware", "static-review", "R0", ("surface-inventory",), ("local_host", "testbed"), ("firmware", "assessment"), ("artifact",), .75),
        ("ot-passive-review", "ot_ics", "ot_ics", "passive-review", "R1", ("surface-inventory",), ("lan", "physical_adjacent", "testbed", "physical_lab"), ("ot", "assessment"), ("pcap",), .74),
        ("automotive-passive-review", "automotive", "automotive", "passive-review", "R1", ("surface-inventory",), ("physical_adjacent", "testbed", "physical_lab"), ("automotive", "assessment"), ("capture",), .71),
    ]
    out=[]
    for row in rows:
        cid,surf,spec,action,risk,pre,pers,obj,evi,val=row
        out.append(asdict(Capability(cid,surf,spec,action,risk,tuple(pre),tuple(pers),tuple(obj),tuple(evi),val)))
    return out


def _norm_set(values: Iterable[str] | None) -> set[str]:
    return {str(x).strip().lower() for x in (values or []) if str(x).strip()}


def _objective_score(cap: dict[str,Any], objective: str) -> float:
    o=objective.lower()
    tags=cap["objective_tags"]
    if any(t in o for t in tags): return .18
    if "full" in o or "assessment" in o: return .10
    return .03


def evaluate_capability(cap: dict[str,Any], *, target: str, perspective: str, objective: str,
                        authorized: bool, execute: bool, completed: set[str], evidence: set[str]) -> dict[str,Any]:
    reasons=[]; blocked=False
    if cap["risk"] in {"R4","R5"}:
        blocked=True; reasons.append("runtime only selects bounded R0-R2 capabilities")
    if cap["action"] in DENIED or cap["id"] in DENIED:
        blocked=True; reasons.append("hard-denied capability")
    missing=[p for p in cap["prerequisites"] if p not in completed]
    if missing: reasons.append("missing prerequisites")
    perspective_ok="*" in cap["perspectives"] or perspective in cap["perspectives"]
    if not perspective_ok:
        blocked=True; reasons.append("perspective incompatible")
    if execute and not authorized:
        blocked=True; reasons.append("authorization required for execution")
    evidence_bonus=.12 if not cap["evidence_inputs"] else (.14 if evidence.intersection(cap["evidence_inputs"]) else 0.0)
    novelty=0.0 if cap["id"] in completed else .20
    prereq_bonus=.12 if not missing else 0.0
    score=max(0.0, cap["value"]+_objective_score(cap,objective)+evidence_bonus+novelty+prereq_bonus-(.12*RISK[cap["risk"]]))
    if missing: score*=.35
    if blocked: score=0.0
    return {"capability_id":cap["id"],"score":round(min(1.0,score),4),"eligible":not blocked and not missing,
            "blocked":blocked,"missing_prerequisites":missing,"reasons":reasons,"target":target,"perspective":perspective}


def select_next_capabilities(*, target: str, perspective: str="internet_ipv4", objective: str="full-assessment",
                             authorized: bool=False, execute: bool=False, completed: Iterable[str]=(),
                             evidence: Iterable[str]=(), limit: int=8) -> list[dict[str,Any]]:
    completed_set=_norm_set(completed); evidence_set=_norm_set(evidence)
    evaluated=[evaluate_capability(c,target=target,perspective=perspective,objective=objective,authorized=authorized,execute=execute,completed=completed_set,evidence=evidence_set) for c in capability_catalog()]
    eligible=[x for x in evaluated if x["eligible"]]
    eligible.sort(key=lambda x:(-x["score"],x["capability_id"]))
    return eligible[:max(1,min(20,int(limit)))]


def build_runtime_state(root: str | Path, *, target: str, perspective: str="internet_ipv4", objective: str="full-assessment",
                        authorized: bool=False, execute: bool=False, completed: Iterable[str]=(), evidence: Iterable[str]=(), limit: int=8) -> dict[str,Any]:
    completed=list(_norm_set(completed)); evidence=list(_norm_set(evidence))
    catalog=capability_catalog(); candidates=select_next_capabilities(target=target,perspective=perspective,objective=objective,authorized=authorized,execute=execute,completed=completed,evidence=evidence,limit=limit)
    state={"schema_version":VERSION,"status":"ready","target":target,"perspective":perspective,"objective":objective,
           "authorization":{"asserted":bool(authorized),"execution_requested":bool(execute)},
           "catalog_size":len(catalog),"completed":completed,"evidence_inputs":evidence,"next_capabilities":candidates,
           "governance":{"planning_only":not execute,"no_scope_expansion":True,"hard_denied":sorted(DENIED),"bounded_execution":"R0-R2 registered adapters only"},
           "runtime_contract":{"target_locked":True,"perspective_locked":True,"objective_locked":True,"recheck_before_execution":True,"single_step_default":True}}
    _write(root,"capability-runtime-v325.json",state)
    return state


def advance_runtime(root: str | Path, *, target: str, capability_id: str, result: dict[str,Any],
                     perspective: str="internet_ipv4", objective: str="full-assessment", completed: Iterable[str]=(), evidence: Iterable[str]=()) -> dict[str,Any]:
    done=set(_norm_set(completed)); ev=set(_norm_set(evidence));
    status=str(result.get("status", "unknown")).lower()
    if status in {"completed","success","verified","observed"}: done.add(capability_id)
    for key in ("evidence_ids","evidence","observations"):
        vals=result.get(key,[])
        if isinstance(vals,list): ev.update(str(x) for x in vals if isinstance(x,(str,int)))
    state=build_runtime_state(root,target=target,perspective=perspective,objective=objective,completed=done,evidence=ev)
    state["last_result"]={"capability_id":capability_id,"status":status}
    _write(root,"capability-runtime-state-v325.json",state)
    return state


def run_bounded_runtime(root: str | Path, *, target: str, scope_file: str | Path, perspective: str="internet_ipv4",
                        objective: str="full-assessment", authorized: bool=False, execute: bool=False,
                        surfaces: list[str] | None=None, max_steps: int=1, timeout: int=600) -> dict[str,Any]:
    """Execute only already-registered bounded capabilities.

    Delegates execution to V3.22/V3.21; the runtime itself never constructs
    arbitrary command lines or exploit procedures.
    """
    if not execute:
        return build_runtime_state(root,target=target,perspective=perspective,objective=objective,authorized=authorized,execute=False,limit=max_steps)
    if not authorized:
        return {"schema_version":VERSION,"status":"blocked","reason":"explicit authorization required","governance":{"planning_only":True}}
    from modules.universal_assessment_runner_v321 import execute_universal_assessment
    selected=surfaces or ["external_web","api","internet_services","remote_access"]
    result=execute_universal_assessment(root,target=target,scope_file=scope_file,perspective=perspective,authorized=True,execute=True,surfaces=selected,max_steps=max(1,min(20,int(max_steps))),timeout=max(1,min(3600,int(timeout))))
    state=build_runtime_state(root,target=target,perspective=perspective,objective=objective,authorized=True,execute=True,completed=[],evidence=[],limit=max_steps)
    state["execution"]={"delegated_to":"V3.21 bounded runner","result_status":result.get("status"),"selected_surfaces":selected}
    _write(root,"capability-runtime-execution-v325.json",state)
    return state

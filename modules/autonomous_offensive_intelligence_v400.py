"""V4.0 Autonomous Offensive Security Intelligence Fabric.

A governed orchestration layer that unifies reasoning, hypotheses, evidence,
exploitation planning, coverage, specialist routing, mission memory and operator
readiness. It plans from existing engine capabilities; it never grants authority,
expands scope, translates prose into arbitrary shell, or executes unrestricted
payloads.
"""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any

VERSION = "4.0.0"

TECHNIQUE_MAP = {
    "access-control": "idor-access-control",
    "authorization": "idor-access-control",
    "input-handling": "xss-reflection",
    "web": "xss-reflection",
    "injection": "sqli-differential",
    "session": "jwt-auth",
    "ssrf": "ssrf",
}

DOMAIN_SIGNALS = {
    "web": ("web", "http", "endpoint", "api", "url", "browser", "xss", "request"),
    "network": ("network", "port", "service", "host", "tcp", "udp", "nmap"),
    "identity": ("role", "login", "auth", "authorization", "identity", "permission", "session"),
    "cloud": ("aws", "cloud", "iam", "s3", "rds", "lambda"),
    "osint": ("osint", "domain", "subdomain", "organization", "public information"),
}

PHASES = {
    "web": ("probe", "crawl_and_scan"),
    "network": ("ports", "recon"),
    "identity": ("authenticated", "ad"),
    "cloud": ("cloud",),
    "osint": ("recon",),
}


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:20]


def _text(*values: Any) -> str:
    return " ".join(str(v or "") for v in values).lower()


def _inventory(root: Path) -> list[dict[str, Any]]:
    ev = root / "evidence"
    out=[]
    if not ev.is_dir(): return out
    for p in sorted(ev.rglob("*")):
        if not p.is_file() or p.name.startswith("."): continue
        try:
            b=p.read_bytes()
            if b:
                out.append({"name":str(p.relative_to(ev)),"size":len(b),"sha256":hashlib.sha256(b).hexdigest()})
        except OSError: pass
    return out


def _load_json(path: Path, default: Any) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default
    except (OSError, ValueError, TypeError): return default


def mission_memory(root: Path, fingerprint: str) -> dict[str, Any]:
    path=root/"evidence"/"mission-memory-v400.json"
    data=_load_json(path,{"schema_version":VERSION,"missions":[]})
    missions=data.get("missions",[]) if isinstance(data,dict) else []
    return {"schema_version":VERSION,"fingerprint":fingerprint,"known_missions":len(missions),"memory_path":str(path),"learning_policy":"validated lessons only; historical cases are hypotheses, never proof"}


def hypotheses(objective: str, story: str, prior: dict[str,Any] | None) -> list[dict[str,Any]]:
    t=_text(objective,story); hs=[]
    rules=[
      ("access-control-object",("role","object id","object ids","different data","endpoint behaves strangely"),"Possible object-level access-control inconsistency","access-control",1.0,"authenticated"),
      ("role-api-differential",("api","two roles","different data","role"),"Possible role-dependent API behavior","authorization",0.9,"authenticated"),
      ("parser-disagreement",("strange","unexpected","encoding","normalization","parser"),"Possible parser/representation disagreement","input-handling",0.7,"web"),
      ("injection-signal",("query","database","parameter","sql","input"),"Possible input-to-query injection path","injection",0.65,"web"),
      ("session-boundary",("login","session","token","jwt","role"),"Possible session/authorization boundary issue","session",0.6,"authenticated"),
    ]
    seen=set()
    for hid,signals,title,klass,priority,phase in rules:
        hits=[s for s in signals if s in t]
        if hits:
            hs.append({"id":hid,"title":title,"class":klass,"priority":priority,"confidence":"context-supported","signals":hits,"required_phase":phase,"finding_claim":False,"evidence_required":True,"status":"unresolved"})
            seen.add(hid)
    for h in (prior or {}).get("hypotheses",[]):
        if isinstance(h,dict) and h.get("id") and h["id"] not in seen:
            c=dict(h); c["persistence"]="carried-forward"; hs.append(c)
    return sorted(hs,key=lambda x:(-float(x.get("priority",0)),x.get("id","")))


def dependency_analysis(hs: list[dict[str,Any]], actions: list[dict[str,Any]], evidence: list[dict[str,Any]]) -> list[dict[str,Any]]:
    successful_phases={str(e.get("phase")) for e in evidence if e.get("evidence_produced")}
    blocked={str(a.get("phase")) for a in actions if a.get("status") in {"blocked","unavailable","skipped"}}
    deps=[]
    for h in hs:
        phase=h.get("required_phase")
        if phase in successful_phases: state="satisfied"; reason="verified evidence exists for required phase"
        elif phase in blocked: state="blocked"; reason=f"required {phase} capability is blocked or unavailable"
        else: state="missing"; reason=f"no verified evidence from required {phase} capability"
        deps.append({"hypothesis_id":h.get("id"),"dependency":phase,"state":state,"reason":reason,"authority_change":False})
    return deps


def next_tests(hs: list[dict[str,Any]], deps: list[dict[str,Any]]) -> list[dict[str,Any]]:
    out=[]
    for h in hs:
        d=next((x for x in deps if x["hypothesis_id"]==h["id"]),None)
        if not d: continue
        technique=TECHNIQUE_MAP.get(h.get("class"))
        out.append({"hypothesis_id":h["id"],"priority":h.get("priority",0),"test":f"Run governed {h.get('required_phase')} validation focused on: {h.get('title')}","required_phase":h.get("required_phase"),"dependency":d,"exploitation_technique":technique,"proof_goal":"obtain reproducible evidence that confirms or disproves the hypothesis","finding_claim":False})
    return sorted(out,key=lambda x:(-float(x.get("priority",0)),x["hypothesis_id"]))[:10]


def specialist_priorities(objective: str, story: str, hs: list[dict[str,Any]]) -> list[dict[str,Any]]:
    t=_text(objective,story); out=[]
    for domain,signals in DOMAIN_SIGNALS.items():
        score=sum(1 for s in signals if s in t)
        score += sum(2 for h in hs if h.get("required_phase") in PHASES.get(domain,()))
        if score: out.append({"specialist":domain,"score":score,"phases":list(PHASES[domain]),"reason":"mission signals and unresolved hypotheses"})
    return sorted(out,key=lambda x:(-x["score"],x["specialist"]))


def coverage(root: Path, hs: list[dict[str,Any]]) -> dict[str,Any]:
    names={x["name"].lower() for x in _inventory(root)}
    domains={d:any(any(s in n for s in sigs) for n in names) for d,sigs in DOMAIN_SIGNALS.items()}
    return {"domains":domains,"gaps":[d for d,v in domains.items() if not v],"hypothesis_driven_gaps":[h["id"] for h in hs],"coverage_is_not_vulnerability_proof":True}


def attack_chain(hs: list[dict[str,Any]], tests: list[dict[str,Any]]) -> dict[str,Any]:
    chains=[]
    for h in hs[:5]:
        t=next((x for x in tests if x["hypothesis_id"]==h["id"]),None)
        chains.append({"hypothesis_id":h["id"],"steps":["establish prerequisite","execute governed validation","capture verified evidence","reassess hypothesis","if confirmed, invoke existing bounded exploitation assurance"],"technique":(t or {}).get("exploitation_technique"),"stop_if_unverified":True})
    return {"chains":chains,"policy":"planning only; existing authorization, scope and approval gates remain authoritative"}


def build(*, root: Path, client: str, target: str, scope: str, objective: str, story: str, loop_result: dict[str,Any]) -> dict[str,Any]:
    actions=[a for r in loop_result.get("rounds",[]) for a in r.get("actions",[]) if isinstance(a,dict)]
    evidence=[a for a in actions if a.get("evidence_produced")]
    fp=_hash({"client":client,"target":target,"scope":scope,"objective":objective,"story":story})
    prior=_load_json(root/"evidence"/"autonomous-offensive-intelligence-v400.json",{})
    hs=hypotheses(objective,story,prior)
    deps=dependency_analysis(hs,actions,evidence)
    tests=next_tests(hs,deps)
    blocked=[d for d in deps if d["state"]=="blocked"]
    unresolved=bool(hs)
    if blocked and unresolved: status="blocked_pending_evidence"
    elif unresolved: status="ready_for_operator"
    elif evidence: status="converged"
    else: status="partial"
    inventory=_inventory(root)
    state={"schema_version":VERSION,"status":status,"generated_at":time.time(),"mission_fingerprint":fp,"client":client,"target":target,"scope":scope,"objective":objective,"story":story,
      "hypotheses":hs,"dependencies":deps,"next_tests":tests,"specialist_priorities":specialist_priorities(objective,story,hs),"attack_chain":attack_chain(hs,tests),"coverage":coverage(root,hs),"evidence":inventory,
      "mission_memory":mission_memory(root,fp),"decision":{"finding_claims":"none without verified evidence","why_not_converged":"blocked dependencies or unresolved hypotheses" if unresolved else "no unresolved hypotheses","scope_expansion":False,"authority_grant":False},
      "metrics":{"verified_evidence_artifacts":len(evidence),"successful_executions":sum(1 for a in actions if a.get("execution_status") in {"completed","partial"}),"hypotheses":len(hs),"blocked_dependencies":len(blocked)},
      "governance":{"authorization_required":True,"scope_policy_authoritative":True,"approval_required_for_sensitive_actions":True,"registered_entrypoints_only":True,"no_arbitrary_shell":True,"no_scope_expansion":True,"no_unverified_finding_claims":True}}
    return state


def write(root:Path,state:dict[str,Any])->None:
    ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    (ev/"autonomous-offensive-intelligence-v400.json").write_text(json.dumps(state,indent=2,sort_keys=True),encoding="utf-8")

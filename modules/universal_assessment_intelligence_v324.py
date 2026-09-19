"""V3.24 Universal Assessment Intelligence.

Evidence reasoning above the V3.23 execution graph.  Planning/evidence only:
this module never grants authority or synthesizes an exploit adapter.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, math, re, time

VERSION = "3.24.0"
DENIED_AUTONOMY = {
    "unrestricted_rce", "destructive_impact", "covert_c2",
    "uncontrolled_propagation", "real_data_exfiltration",
    "credential_spraying_at_scale", "carrier_bypass",
}
SURFACE_DOMAINS = {
    "external_web":"web", "api":"web", "dns_certificate":"network",
    "internet_services":"network", "remote_access":"remote",
    "endpoint_windows":"endpoint", "endpoint_linux":"endpoint", "endpoint_macos":"endpoint",
    "identity_directory":"identity", "cloud":"cloud", "saas":"cloud",
    "containers":"container", "virtualization":"virtualization", "network_devices":"network",
    "wireless":"wireless", "mobile_android":"mobile", "mobile_ios":"mobile",
    "iot":"iot", "firmware":"firmware", "hardware_debug":"hardware", "ot_ics":"ot_ics",
    "automotive":"automotive", "databases":"data", "storage_backup":"data",
    "email_collaboration":"identity", "supply_chain":"supply_chain", "source_code_ci_cd":"source",
    "secrets_keys":"secrets", "observability_management":"management",
    "third_party_integrations":"integration", "client_browser_desktop":"client",
    "human_social":"human", "physical_facility":"physical", "ai_ml":"ai_ml",
    "cellular_telecom":"cellular",
}
DOMAIN_ORDER = ["web","network","identity","cloud","endpoint","mobile","wireless","remote","data","source","secrets","container","management","integration","client","iot","firmware","hardware","ot_ics","automotive","cellular","ai_ml","supply_chain","human","physical","virtualization"]
IMPACT_WEIGHTS = {"confidentiality":.34,"integrity":.33,"availability":.33}

@dataclass(frozen=True)
class Finding:
    id: str
    surface: str
    domain: str
    title: str
    status: str
    confidence: float
    evidence_quality: float
    severity: float
    exploitability: float
    impact: float
    prerequisites: tuple[str, ...]
    source: str
    fresh: bool = True


def _write(root: str | Path, name: str, obj: Any) -> Path:
    p = Path(root) / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _load_json(path: str | Path) -> Any:
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


def _redact(v: Any) -> Any:
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if any(t in k.lower() for t in ("password","secret","token","private_key","credential_value")):
                out[k] = "[REDACTED]"
            else: out[k] = _redact(x)
        return out
    if isinstance(v, list): return [_redact(x) for x in v]
    return v


def normalize_evidence(observations: Iterable[Any] | None = None) -> list[dict[str, Any]]:
    out=[]
    for i, raw in enumerate(observations or []):
        if not isinstance(raw, dict): continue
        x=_redact(raw)
        x.setdefault("id", f"obs-{i+1}")
        x.setdefault("status", "observed")
        x.setdefault("source", "operator-input")
        out.append(x)
    return out


def ingest_baseline(baseline: str | Path | dict | list | None) -> list[dict[str, Any]]:
    if baseline is None: return []
    if isinstance(baseline, (str, Path)):
        p=Path(baseline)
        if not p.is_file(): return []
        raw=_load_json(p)
    else: raw=baseline
    if isinstance(raw, dict):
        for key in ("observations","evidence","findings","results","items"):
            if isinstance(raw.get(key), list): return normalize_evidence(raw[key])
        return normalize_evidence([raw])
    return normalize_evidence(raw if isinstance(raw,list) else [])


def _num(x: Any, default: float=0.5) -> float:
    try: return max(0.0,min(1.0,float(x)))
    except (TypeError,ValueError): return default


def evidence_quality(obs: dict[str, Any]) -> float:
    explicit=_num(obs.get("evidence_quality"), -1)
    if explicit >= 0: return explicit
    score=.25
    if obs.get("source") not in (None,"operator-input"): score += .15
    if obs.get("timestamp") or obs.get("observed_at"): score += .10
    if obs.get("raw_artifact") or obs.get("artifact") or obs.get("evidence"): score += .15
    if obs.get("validated") is True or str(obs.get("status","")).lower() in {"validated","verified","confirmed"}: score += .40
    if obs.get("retest") is True: score += .10
    if obs.get("reproducible") is True: score += .05
    return min(1.0,score)


def state_model(observations: Iterable[Any], *, now: float | None=None, ttl_seconds: int=86400) -> dict[str,Any]:
    now=now or time.time(); records=[]
    for o in normalize_evidence(observations):
        ts=o.get("timestamp",o.get("observed_at"))
        try: age=max(0,now-float(ts)) if ts else None
        except (TypeError,ValueError): age=None
        fresh = age is None or age <= ttl_seconds
        status=str(o.get("status","observed")).lower()
        records.append({"id":o["id"],"status":status,"age_seconds":age,"fresh":fresh,"stale":not fresh,"invalidates":[]})
    stale_ids={r["id"] for r in records if r["stale"]}
    for r in records:
        if r["stale"]: r["invalidates"]=["confidence","exploitability","impact"]
    return {"ttl_seconds":ttl_seconds,"records":records,"fresh_count":len(records)-len(stale_ids),"stale_count":len(stale_ids),"revalidation_required":bool(stale_ids)}


def _surface_for(o: dict[str,Any]) -> str:
    s=str(o.get("surface",o.get("attack_surface",o.get("category","")))).strip().lower().replace(" ","_")
    if s in SURFACE_DOMAINS: return s
    text=" ".join(str(o.get(k,"")) for k in ("title","name","description","type","service","technology")).lower()
    patterns=[("api","api"),("web","web|http|https|xss|sqli"),("dns","dns|certificate"),("identity_directory","active.?directory|ldap|kerberos|identity"),("cloud","aws|azure|gcp|cloud"),("wireless","wifi|wireless|ble"),("mobile_android","android|apk"),("mobile_ios","ios|ipa"),("firmware","firmware|embedded"),("ot_ics","ics|scada|plc|ot"),("automotive","can bus|automotive"),("network_devices","router|switch|snmp"),("remote_access","ssh|rdp|winrm|smb"),("containers","docker|kubernetes|container"),("secrets_keys","secret|api key|private key")]
    for surf,pat in patterns:
        if re.search(pat,text): return surf
    return "internet_services"


def extract_findings(observations: Iterable[Any]) -> list[dict[str,Any]]:
    findings=[]
    for i,o in enumerate(normalize_evidence(observations)):
        surf=_surface_for(o); domain=SURFACE_DOMAINS.get(surf,"unknown")
        title=str(o.get("title",o.get("name",o.get("finding",f"Observation {i+1}"))))
        status=str(o.get("status","observed")).lower()
        q=evidence_quality(o)
        conf=_num(o.get("confidence"),q)
        sev=_num(o.get("severity",o.get("risk")),.5)
        exp=_num(o.get("exploitability"),.35 if any(x in title.lower() for x in ("vulnerab","expos","misconfig","injection")) else .2)
        impact=_num(o.get("impact"),sev)
        prereq=tuple(str(x) for x in (o.get("prerequisites") or []))
        rec=asdict(Finding(f"finding-{i+1}",surf,domain,title,status,conf,q,sev,exp,impact,prereq,str(o.get("source","unknown")),True)); rec["source_observation_id"]=o.get("id"); findings.append(rec)
    return findings


def correlate_cross_domain(findings: list[dict[str,Any]]) -> dict[str,Any]:
    edges=[]; groups={}
    for f in findings: groups.setdefault(f["domain"],[]).append(f)
    for i,a in enumerate(findings):
        for b in findings[i+1:]:
            if a["domain"]==b["domain"]: continue
            shared=[]
            at=(a["title"]+" "+a["source"]).lower(); bt=(b["title"]+" "+b["source"]).lower()
            for term in ("identity","auth","token","admin","cloud","api","host","service","dns","network","endpoint","container","secret","certificate"):
                if term in at and term in bt: shared.append(term)
            score=min(1.0,.25 + .15*len(shared) + .25*min(a["evidence_quality"],b["evidence_quality"]))
            if shared or abs(a["impact"]-b["impact"])<.15:
                edges.append({"from":a["id"],"to":b["id"],"relation":"cross-domain-correlation","strength":round(score,4),"signals":shared})
    return {"domains":sorted(groups),"domain_counts":{k:len(v) for k,v in groups.items()},"edges":edges}


def build_exposure_impact_chains(findings: list[dict[str,Any]]) -> list[dict[str,Any]]:
    chains=[]
    for f in findings:
        score=0.30*f["evidence_quality"]+0.25*f["confidence"]+0.20*f["exploitability"]+0.25*f["impact"]
        verdict="candidate" if score>=.45 else "unconfirmed"
        if f["evidence_quality"]<.45: verdict="insufficient-evidence"
        chains.append({"finding_id":f["id"],"surface":f["surface"],"domain":f["domain"],"chain":["exposure","vulnerability_or_condition","exploitability_assessment","access_or_control_effect","objective_or_impact"],"score":round(score,4),"verdict":verdict,"do_not_claim_exploited":True})
    return sorted(chains,key=lambda x:-x["score"])


def rank_attack_paths(findings: list[dict[str,Any]], correlations: dict[str,Any], *, objective="full-assessment", limit=12) -> list[dict[str,Any]]:
    if not findings: return []
    adj={f["id"]:set() for f in findings}
    for e in correlations.get("edges",[]): adj[e["from"]].add(e["to"]); adj[e["to"]].add(e["from"])
    paths=[]
    for f in findings:
        reach=list(adj[f["id"]])[:3]
        base=.30*f["evidence_quality"]+.25*f["exploitability"]+.25*f["impact"]+.20*f["confidence"]
        for other_id in reach or [None]:
            other=next((x for x in findings if x["id"]==other_id),None)
            domains=[f["domain"]]+([other["domain"]] if other else [])
            score=min(1.0,base+(0.15 if other else 0)+(0.05 if objective!="general" else 0))
            paths.append({"path_id":hashlib.sha256((f["id"]+str(other_id)+objective).encode()).hexdigest()[:12],"nodes":[f["id"]]+([other_id] if other else []),"domains":domains,"score":round(score,4),"likelihood":round((f["exploitability"]+(other["exploitability"] if other else f["exploitability"]))/2,4),"impact":round((f["impact"]+(other["impact"] if other else f["impact"]))/2,4),"evidence_strength":round((f["evidence_quality"]+(other["evidence_quality"] if other else f["evidence_quality"]))/2,4),"prerequisites":sorted(set(f["prerequisites"]+(other["prerequisites"] if other else ()))),"status":"candidate"})
    paths.sort(key=lambda x:-x["score"])
    return paths[:limit]


def generate_hypotheses(findings: list[dict[str,Any]], state: dict[str,Any]) -> list[dict[str,Any]]:
    out=[]
    for f in findings:
        confidence=f["confidence"]*f["evidence_quality"]
        out.append({"hypothesis_id":"H-"+f["id"],"claim":f["title"],"supporting_evidence":[f["id"]],"confidence":round(confidence,4),"state":"confirmed" if confidence>=.72 else "candidate" if confidence>=.42 else "unknown","cheapest_discriminator":"revalidate-source-artifact","blocked_by":["stale-evidence"] if not f["fresh"] else []})
    return out


def build_remediation_retest(findings: list[dict[str,Any]]) -> list[dict[str,Any]]:
    return [{"finding_id":f["id"],"remediation":["remove or mitigate the identified exposure/condition","add preventive control where appropriate","add detection/monitoring coverage"],"retest":{"required":True,"method":"repeat the original bounded evidence test","success_criteria":"original exposure is absent and control evidence is present"},"priority":round(.45*f["severity"]+.30*f["impact"]+.25*(1-f["evidence_quality"]),4)} for f in findings]


def build_detection_validation(findings: list[dict[str,Any]]) -> list[dict[str,Any]]:
    out=[]
    for f in findings:
        out.append({"finding_id":f["id"],"technique_context":f["domain"],"validation_plan":["identify expected telemetry","map available telemetry to the relevant ATT&CK behavior","validate alert/log visibility using authorized non-destructive evidence","record gaps without evasion"],"status":"planned"})
    return out


def build_mission_plan(paths: list[dict[str,Any]], findings: list[dict[str,Any]], *, objective: str) -> dict[str,Any]:
    steps=[]
    for i,p in enumerate(paths[:10],1):
        steps.append({"step":i,"path_id":p["path_id"],"action":"evidence-review-and-bounded-validation","domains":p["domains"],"value_score":p["score"],"requires":"existing scope/authorization/ROE/approval controls","success":"stronger evidence or a disproven hypothesis","fallback":"perspective shift or alternate non-destructive test"})
    return {"objective":objective,"strategy":"observe → correlate → hypothesize → validate → revalidate → report","steps":steps,"stop_conditions":["scope change","authorization invalidated","kill switch","evidence integrity failure","unsafe or denied autonomy class"]}


def professional_report(findings, paths, hypotheses, remediation, detection, state, *, target, objective) -> dict[str,Any]:
    return {"schema_version":VERSION,"title":"Universal Security Assessment Report","target":target,"objective":objective,"executive_summary":{"findings":len(findings),"candidate_attack_paths":len(paths),"stale_evidence":state["stale_count"],"confidence_note":"scanner output is not treated as proof of exploitability"},"findings":findings,"attack_paths":paths,"hypotheses":hypotheses,"remediation_retest":remediation,"detection_validation":detection,"limitations":["planning/evidence reasoning only","no exploit, persistence, exfiltration, evasion, propagation or destructive execution is granted by this layer"]}


def build_assessment_intelligence(root: str | Path, *, target: str, observations=None, baseline=None, objective="full-assessment", ttl_seconds=86400, max_paths=12) -> dict[str,Any]:
    obs=normalize_evidence(observations)+ingest_baseline(baseline)
    # stable de-duplication by canonical JSON
    seen=set(); dedup=[]
    for o in obs:
        key=json.dumps(o,sort_keys=True)
        if key not in seen: seen.add(key); dedup.append(o)
    findings=extract_findings(dedup)
    state=state_model(dedup,ttl_seconds=ttl_seconds)
    for f in findings:
        rec=next((x for x in state["records"] if x["id"]==f.get("source_observation_id")),None)
        f["fresh"]=bool(rec["fresh"]) if rec else True
        if not f["fresh"]: f["confidence"]*=.55; f["evidence_quality"]*=.70
    correlations=correlate_cross_domain(findings)
    chains=build_exposure_impact_chains(findings)
    paths=rank_attack_paths(findings,correlations,objective=objective,limit=max_paths)
    hypotheses=generate_hypotheses(findings,state)
    remediation=build_remediation_retest(findings)
    detection=build_detection_validation(findings)
    mission=build_mission_plan(paths,findings,objective=objective)
    report=professional_report(findings,paths,hypotheses,remediation,detection,state,target=target,objective=objective)
    governance={"planning_only":True,"authorization_still_required":True,"scope_recheck_before_execution":True,"approval_for_consequential_actions":True,"denied_autonomy_classes":sorted(DENIED_AUTONOMY)}
    data={"schema_version":VERSION,"status":"ready","target":target,"objective":objective,"evidence_count":len(dedup),"findings":findings,"state":state,"cross_domain_correlation":correlations,"exposure_impact_chains":chains,"attack_paths":paths,"hypotheses":hypotheses,"remediation_retest":remediation,"detection_validation":detection,"mission_plan":mission,"report":report,"governance":governance,"generated_at":time.time()}
    _write(root,"assessment-intelligence-v324.json",data)
    _write(root,"assessment-report-v324.json",report)
    return data


def build_attack_paths(root: str | Path, *, target: str, observations=None, baseline=None, objective="full-assessment", max_paths=12):
    data=build_assessment_intelligence(root,target=target,observations=observations,baseline=baseline,objective=objective,max_paths=max_paths)
    return {"schema_version":VERSION,"target":target,"objective":objective,"attack_paths":data["attack_paths"],"hypotheses":data["hypotheses"],"governance":data["governance"]}


def build_v324_fabric(root: str | Path, *, target: str, observations=None, baseline=None, objective="full-assessment", max_paths=12):
    return build_assessment_intelligence(root,target=target,observations=observations,baseline=baseline,objective=objective,max_paths=max_paths)

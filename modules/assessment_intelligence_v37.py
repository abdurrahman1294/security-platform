"""V3.7 assessment intelligence primitives.

These modules are deliberately evidence-driven: they normalize observations,
map dependencies, rank investigation paths, and expose coverage gaps. They do
not expand scope or perform consequential target actions.
"""
from __future__ import annotations
import hashlib, ipaddress, json, re
from pathlib import Path
from urllib.parse import urlsplit
from modules.atomic_io import atomic_write_json, atomic_write_text

SCHEMA = "3.7"

def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return default

def rows(doc):
    if isinstance(doc, list): return doc
    if isinstance(doc, dict):
        for key in ("findings", "observations", "services", "assets", "resources", "relationships", "tests", "nodes"):
            value = doc.get(key)
            if isinstance(value, list): return value
    return []

def canonical_asset(value: object) -> str:
    s = str(value or "").strip().lower().rstrip(".")
    if not s: return ""
    if "://" in s:
        p = urlsplit(s)
        if p.hostname:
            host = p.hostname.lower().rstrip(".")
            return host[4:] if host.startswith("www.") else host
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        pass
    if s.startswith("www."): s = s[4:]
    return re.sub(r"[^a-z0-9._:-]", "", s)

def stable_id(prefix: str, value: str) -> str:
    return prefix + "-" + hashlib.sha256(value.encode()).hexdigest()[:14]

def asset_identity(root: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True, exist_ok=True)
    candidates=[]
    files=[p for p in ev.glob("*.json") if p.name not in {"asset-identity-v37.json"}]
    for path in files:
        doc=load_json(path,{})
        for i,row in enumerate(rows(doc)):
            if not isinstance(row,dict): continue
            vals=[]
            for key in ("asset","host","hostname","address","url","resource","device","principal","name"):
                v=row.get(key)
                if v: vals.append((key, canonical_asset(v)))
            for key,val in vals:
                if val: candidates.append({"canonical":val,"source":path.name,"field":key,"row":i})
    groups={}
    for c in candidates: groups.setdefault(c["canonical"],[]).append(c)
    identities=[]
    for canonical, refs in sorted(groups.items()):
        aliases=sorted({r["canonical"] for r in refs})
        identities.append({"asset_id":stable_id("A",canonical),"canonical":canonical,"aliases":aliases,"sources":refs,"confidence":1.0 if len(refs)>1 else 0.8})
    out={"schema_version":SCHEMA,"status":"completed","identity_count":len(identities),"identities":identities,"limitations":["Identity is derived from supplied evidence only","Canonicalization does not prove ownership or reachability"]}
    atomic_write_json(ev/"asset-identity-v37.json",out); return out

def dependency_map(root: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True, exist_ok=True)
    identities=load_json(ev/"asset-identity-v37.json",{})
    known={x["canonical"]:x["asset_id"] for x in identities.get("identities",[]) if isinstance(x,dict)}
    edges=[]
    keys=("depends_on","dependency","backend","database","service","upstream","downstream","parent","cluster")
    for path in ev.glob("*.json"):
        if path.name=="dependency-map-v37.json": continue
        doc=load_json(path,{})
        for i,row in enumerate(rows(doc)):
            if not isinstance(row,dict): continue
            src=""
            for k in ("asset","host","hostname","address","resource","device","name"):
                if row.get(k): src=canonical_asset(row[k]); break
            if not src or src not in known: continue
            for k in keys:
                val=row.get(k)
                vals=val if isinstance(val,list) else [val]
                for v in vals:
                    dst=canonical_asset(v)
                    if dst and dst in known and dst!=src:
                        edge={"src":known[src],"dst":known[dst],"relationship":k,"source":path.name,"row":i,"confidence":0.75}
                        if edge not in edges: edges.append(edge)
    out={"schema_version":SCHEMA,"status":"completed","edge_count":len(edges),"edges":edges,"limitations":["Only explicit dependency-like fields are used","Dependencies are hypotheses until independently validated"]}
    atomic_write_json(ev/"dependency-map-v37.json",out); return out

def normalize_authenticated(root: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True, exist_ok=True)
    source=load_json(ev/"auth-role-analysis-v35.json",{})
    raw=rows(source)
    normalized=[]
    for i,r in enumerate(raw):
        if not isinstance(r,dict): continue
        role=str(r.get("role") or r.get("subject_role") or "unknown")
        action=str(r.get("action") or r.get("operation") or r.get("test") or "unknown")
        observed=r.get("observed") if "observed" in r else r.get("result")
        expected=r.get("expected") or r.get("expected_result")
        if isinstance(observed,str): observed=observed.lower() in {"allow","allowed","true","pass","success"}
        if isinstance(expected,str): expected=expected.lower() in {"allow","allowed","true","pass","success"}
        mismatch = isinstance(observed,bool) and isinstance(expected,bool) and observed != expected
        normalized.append({"test_id":r.get("test_id") or stable_id("T",f"{role}|{action}|{i}"),"role":role,"action":action,"expected":expected,"observed":observed,"mismatch":mismatch,"asset":canonical_asset(r.get("asset") or r.get("host")),"source":"auth-role-analysis-v35.json"})
    out={"schema_version":SCHEMA,"status":"completed","test_count":len(normalized),"mismatch_count":sum(x["mismatch"] for x in normalized),"tests":normalized,"interpretation":"A mismatch is an evidence item requiring authorized reproduction, not proof of exploitability."}
    atomic_write_json(ev/"authenticated-evidence-v37.json",out); return out

def rank_attack_paths(root: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    fabric=load_json(ev/"intelligence-fabric-v36.json",{})
    deps=load_json(ev/"dependency-map-v37.json",{})
    findings=load_json(ev/"normalized-findings.json",{})
    fs=rows(findings)
    by_asset={}
    for f in fs:
        if isinstance(f,dict): by_asset.setdefault(canonical_asset(f.get("asset") or f.get("host")),[]).append(f)
    paths=[]
    for e in deps.get("edges",[]):
        src,dst=e.get("src"),e.get("dst")
        src_find=by_asset.get(src,[]); dst_find=by_asset.get(dst,[])
        severity=sum({"critical":40,"high":30,"medium":20,"low":10,"info":2}.get(str(f.get("severity")).lower(),0) for f in src_find+dst_find)
        evidence_bonus=10 if any(r.get("asset") in {src,dst} for r in fabric.get("cross_domain_relationships",[])) else 0
        score=min(100, severity+evidence_bonus+15)
        paths.append({"path_id":stable_id("P",f"{src}|{dst}|{e.get('relationship')}"),"src":src,"dst":dst,"relationship":e.get("relationship"),"score":score,"priority":"high" if score>=70 else "medium" if score>=40 else "low","basis":{"finding_count":len(src_find)+len(dst_find),"dependency_confidence":e.get("confidence",0),"cross_domain_evidence":bool(evidence_bonus)}})
    paths.sort(key=lambda x:(-x["score"],x["path_id"]))
    out={"schema_version":SCHEMA,"status":"completed","path_count":len(paths),"paths":paths[:500],"interpretation":"Rankings prioritize evidence-rich investigation paths; they do not assert reachability or provide exploit instructions."}
    atomic_write_json(ev/"attack-path-ranking-v37.json",out); return out

def coverage_gaps(root: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    expected={
      "asset_identity":"asset-identity-v37.json","dependency_mapping":"dependency-map-v37.json","authenticated_evidence":"authenticated-evidence-v37.json","attack_path_ranking":"attack-path-ranking-v37.json","finding_dedup":"finding-dedup-v25.json","remediation":"remediation-tracking-v35.json","evidence_quality":"evidence-quality-v34.json","report_pack":"report-pack-v34.json"}
    gaps=[{"capability":k,"artifact":v} for k,v in expected.items() if not (ev/v).exists()]
    out={"schema_version":SCHEMA,"status":"completed","coverage":round(100*(len(expected)-len(gaps))/len(expected),1),"expected_count":len(expected),"gap_count":len(gaps),"gaps":gaps}
    atomic_write_json(ev/"coverage-gaps-v37.json",out); return out

def remediation_priority(root: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    findings=load_json(ev/"normalized-findings.json",{})
    weights={"critical":100,"high":75,"medium":50,"low":25,"info":5}
    items=[]
    for i,f in enumerate(rows(findings)):
        if not isinstance(f,dict): continue
        sev=str(f.get("severity") or "info").lower(); base=weights.get(sev,5)
        asset=canonical_asset(f.get("asset") or f.get("host"))
        exploit=str(f.get("exploitability") or "unknown").lower()
        impact=str(f.get("impact") or "unknown").lower()
        score=base+(15 if exploit in {"high","confirmed"} else 0)+(10 if impact in {"high","critical"} else 0)
        items.append({"finding_id":f.get("normalized_id") or stable_id("F",json.dumps(f,sort_keys=True,default=str)),"asset":asset,"severity":sev,"priority_score":min(125,score),"priority":"P0" if score>=100 else "P1" if score>=75 else "P2" if score>=50 else "P3"})
    items.sort(key=lambda x:(-x["priority_score"],x["finding_id"]))
    out={"schema_version":SCHEMA,"status":"completed","items":items,"interpretation":"Prioritization is a triage aid; business context and asset criticality must be reviewed by the engagement team."}
    atomic_write_json(ev/"remediation-priority-v37.json",out); return out

def engagement_state(root: str | Path, transition: str | None = None) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    p=ev/"engagement-state-v37.json"; state=load_json(p,{"state":"initialized","history":[]})
    allowed={"initialized":{"running"},"running":{"paused","completed","failed"},"paused":{"running","closed"},"failed":{"running","closed"},"completed":{"closed"},"closed":set()}
    if transition:
        current=state.get("state","initialized")
        if transition not in allowed.get(current,set()): raise ValueError(f"invalid transition: {current} -> {transition}")
        state["state"]=transition; state.setdefault("history",[]).append({"from":current,"to":transition})
    state["schema_version"]=SCHEMA
    atomic_write_json(p,state); return state

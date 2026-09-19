"""V3.8 intelligence fabric.

Evidence-only correlation and planning primitives.  This module intentionally
never performs target actions, creates credentials, or emits exploit steps.
"""
from __future__ import annotations
import hashlib, json, re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from modules.atomic_io import atomic_write_json, atomic_write_text

SCHEMA = "3.8"
SEVERITY = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}

def load(path, default=None):
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError): return default if default is not None else {}

def rows(doc):
    if isinstance(doc, list): return doc
    if isinstance(doc, dict):
        for k in ("findings","observations","assets","services","relationships","tests","nodes","edges","resources","paths"):
            if isinstance(doc.get(k), list): return doc[k]
    return []

def sid(prefix, seed): return prefix + "-" + hashlib.sha256(str(seed).encode()).hexdigest()[:14]

def norm_asset(v):
    s=str(v or "").strip().lower().rstrip(".")
    s=re.sub(r"^https?://", "", s).split("/",1)[0]
    return s[4:] if s.startswith("www.") else s

def now(): return datetime.now(timezone.utc).isoformat()

def asset_context(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    identities=load(ev/"asset-identity-v37.json",{}).get("identities",[])
    findings=rows(load(ev/"normalized-findings.json",{}))
    deps=load(ev/"dependency-map-v37.json",{}).get("edges",[])
    context=[]
    byid={x.get("asset_id"):x for x in identities if isinstance(x,dict)}
    for a in identities:
        aid=a.get("asset_id"); canon=norm_asset(a.get("canonical")); fs=[f for f in findings if norm_asset(f.get("asset") or f.get("host"))==canon]
        sev=max((SEVERITY.get(str(f.get("severity", "info")).lower(),5) for f in fs), default=0)
        incoming=sum(1 for e in deps if e.get("dst")==aid); outgoing=sum(1 for e in deps if e.get("src")==aid)
        criticality=min(100, 10 + sev*0.6 + incoming*8 + outgoing*4)
        context.append({"asset_id":aid,"canonical":canon,"criticality":round(criticality,1),"finding_count":len(fs),"dependency_in":incoming,"dependency_out":outgoing})
    out={"schema_version":SCHEMA,"status":"completed","assets":context,"rule":"Criticality is triage context, not proof of business importance."}
    atomic_write_json(ev/"asset-context-v38.json",out); return out

def multi_hop_paths(root, max_hops=4):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    deps=load(ev/"dependency-map-v37.json",{}).get("edges",[])
    findings=rows(load(ev/"normalized-findings.json",{})); ctx=load(ev/"asset-context-v38.json",{}).get("assets",[])
    score_asset={x.get("asset_id"):x.get("criticality",0) for x in ctx}
    sev_by={}
    for f in findings:
        key=norm_asset(f.get("asset") or f.get("host")); sev_by[key]=max(sev_by.get(key,0),SEVERITY.get(str(f.get("severity","info")).lower(),5))
    adj=defaultdict(list)
    for e in deps:
        if e.get("src") and e.get("dst"): adj[e["src"]].append(e)
    paths=[]
    for start in sorted(adj):
        q=deque([(start,[start],[])]); seen={(start,)}
        while q:
            node,nodes,edges=q.popleft()
            if edges:
                vals=[score_asset.get(n,0) for n in nodes]
                score=min(100, round(sum(vals)/max(1,len(vals)) + 8*len(edges) + max(vals,default=0)*0.15,1))
                paths.append({"path_id":sid("MP", "|".join(nodes)),"nodes":nodes,"relationships":[e.get("relationship") for e in edges],"score":score,"priority":"high" if score>=70 else "medium" if score>=40 else "low","confidence":round(min(1,sum(e.get("confidence",0) for e in edges)/len(edges)),2)})
            if len(edges)>=max_hops: continue
            for e in sorted(adj.get(node,[]), key=lambda x:(x.get("dst", ""),x.get("relationship", ""))):
                nxt=e.get("dst")
                if nxt in nodes: continue
                nn=tuple(nodes+[nxt])
                if nn in seen: continue
                seen.add(nn); q.append((nxt,nodes+[nxt],edges+[e]))
    unique={p["path_id"]:p for p in paths}
    result=sorted(unique.values(),key=lambda x:(-x["score"],x["path_id"]))[:1000]
    out={"schema_version":SCHEMA,"status":"completed","max_hops":max_hops,"path_count":len(result),"paths":result,"interpretation":"Multi-hop paths are investigation hypotheses; reachability and exploitability require separate authorized validation."}
    atomic_write_json(ev/"multi-hop-attack-paths-v38.json",out); return out

def calibrate_findings(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    findings=rows(load(ev/"normalized-findings.json",{})); quality=load(ev/"evidence-quality-v34.json",{})
    quality_score=quality.get("score", quality.get("overall_score", 0))
    outrows=[]
    for i,f in enumerate(findings):
        sev=SEVERITY.get(str(f.get("severity","info")).lower(),5)
        signals=0
        signals += 25 if f.get("url") or f.get("endpoint") or f.get("matched-at") else 0
        signals += 20 if f.get("reference") or f.get("cve") else 0
        signals += 20 if f.get("validation_state") in {"validated","confirmed"} else 0
        signals += 15 if f.get("evidence") else 0
        provenance=15 if f.get("source") or f.get("scanner") or f.get("tool") else 0
        score=min(100, signals+provenance+min(10, float(quality_score or 0)/10))
        state="confirmed" if f.get("validation_state")=="confirmed" else "validated" if f.get("validation_state")=="validated" else "needs-validation" if score>=55 else "suspected"
        outrows.append({"finding_id":f.get("normalized_id") or f.get("finding_id") or sid("F",json.dumps(f,sort_keys=True,default=str)),"confidence":round(score,1),"state":state,"severity":str(f.get("severity","info")).lower(),"provenance_strength":provenance,"evidence_quality_context":quality_score})
    out={"schema_version":SCHEMA,"status":"completed","finding_count":len(outrows),"findings":outrows,"rule":"Confidence never upgrades a finding to confirmed without explicit validation evidence."}
    atomic_write_json(ev/"finding-confidence-v38.json",out); return out

def provenance_chain(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    entries=[]
    for p in sorted(ev.glob("*.json")):
        if p.name=="provenance-chain-v38.json": continue
        try:
            raw=p.read_bytes(); digest=hashlib.sha256(raw).hexdigest(); doc=json.loads(raw)
        except Exception: continue
        entries.append({"artifact":p.name,"sha256":digest,"schema_version":doc.get("schema_version") if isinstance(doc,dict) else None})
    chain=[]; prev="GENESIS"
    for e in entries:
        link=hashlib.sha256((prev+e["artifact"]+e["sha256"]).encode()).hexdigest(); chain.append({**e,"previous":prev,"link":link}); prev=link
    out={"schema_version":SCHEMA,"status":"completed","entry_count":len(chain),"chain":chain}
    atomic_write_json(ev/"provenance-chain-v38.json",out); return out

def remediation_dependencies(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    priority=load(ev/"remediation-priority-v37.json",{}).get("items",[]); ctx={x.get("asset_id"):x for x in load(ev/"asset-context-v38.json",{}).get("assets",[])}
    deps=load(ev/"dependency-map-v37.json",{}).get("edges",[]); impact=defaultdict(int)
    for e in deps: impact[e.get("src")]+=1; impact[e.get("dst")]+=2
    items=[]
    for item in priority:
        aid=next((x.get("asset_id") for x in ctx.values() if x.get("canonical")==norm_asset(item.get("asset"))),None)
        score=min(150, int(item.get("priority_score",0)) + impact.get(aid,0)*5 + int(ctx.get(aid,{}).get("criticality",0)*0.15))
        items.append({**item,"dependency_impact":impact.get(aid,0),"asset_criticality":ctx.get(aid,{}).get("criticality",0),"adjusted_score":score,"retest_required":True})
    items.sort(key=lambda x:(-x["adjusted_score"],x.get("finding_id","")))
    out={"schema_version":SCHEMA,"status":"completed","items":items,"rule":"Dependency impact is advisory; owners must validate business criticality."}
    atomic_write_json(ev/"remediation-dependency-priority-v38.json",out); return out

def session_model(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    tests=rows(load(ev/"authenticated-evidence-v37.json",{})); sessions=[]; groups=defaultdict(list)
    for t in tests: groups[(t.get("role","unknown"),t.get("asset",""))].append(t)
    for (role,asset),items in sorted(groups.items()):
        sessions.append({"session_id":sid("S",f"{role}|{asset}"),"role":role,"asset":asset,"test_count":len(items),"mismatches":sum(bool(x.get("mismatch")) for x in items),"status":"operator-review"})
    out={"schema_version":SCHEMA,"status":"completed","sessions":sessions,"count":len(sessions),"security_rule":"Sensitive credential and token values are not persisted by this model."}
    atomic_write_json(ev/"authenticated-session-model-v38.json",out); return out

def plugin_contract(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    required=["name","version","capabilities","input_schema","output_schema","safety","evidence"]
    examples=[]
    for p in sorted((root/"plugins").glob("*.json")) if (root/"plugins").exists() else []:
        doc=load(p,{})
        missing=[x for x in required if x not in doc]
        examples.append({"plugin":p.name,"valid":not missing,"missing":missing})
    out={"schema_version":SCHEMA,"status":"completed","required_fields":required,"plugins":examples,"contract":"Plugins declare capabilities and evidence outputs; they cannot widen scope or bypass policy."}
    atomic_write_json(ev/"plugin-contract-v38.json",out); return out

def coverage(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    expected={"asset-context":"asset-context-v38.json","multi-hop-paths":"multi-hop-attack-paths-v38.json","confidence-calibration":"finding-confidence-v38.json","provenance-chain":"provenance-chain-v38.json","remediation-dependencies":"remediation-dependency-priority-v38.json","session-model":"authenticated-session-model-v38.json","plugin-contract":"plugin-contract-v38.json"}
    rows_=[{"capability":k,"artifact":v,"present":(ev/v).exists()} for k,v in expected.items()]
    complete=sum(x["present"] for x in rows_); out={"schema_version":SCHEMA,"status":"completed","coverage":round(100*complete/len(rows_),1),"items":rows_}
    atomic_write_json(ev/"coverage-v38.json",out); return out

"""V3.67 Autonomous Attack-Path Intelligence.

Builds an evidence-grounded graph of assets, observations, identities, findings,
trust boundaries and candidate transitions. It ranks next investigations by
information gain and keeps failed paths so the agent does not blindly revisit them.
No node or edge grants execution authority.
"""
from __future__ import annotations
import hashlib, json, re, time
from pathlib import Path
from typing import Any, Iterable

VERSION="3.67.0"

def _norm(s: Any) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower())

def _id(prefix: str, text: str) -> str:
    return prefix+"_"+hashlib.sha256(_norm(text).encode()).hexdigest()[:12]

def build_attack_path(*, target: str, story: str="", findings: Iterable[Any]=(), observations: Iterable[Any]=(), prior_events: Iterable[Any]=()) -> dict[str,Any]:
    findings=list(findings); observations=list(observations); prior=list(prior_events)
    nodes=[{"id":_id("asset",target),"type":"asset","label":target,"confidence":1.0}]
    edges=[]; seen=set()
    def add_node(typ,label,confidence=.5,meta=None):
        nid=_id(typ,label)
        if nid not in {n["id"] for n in nodes}: nodes.append({"id":nid,"type":typ,"label":str(label)[:300],"confidence":round(float(confidence),3),"meta":meta or {}})
        return nid
    for i,f in enumerate(findings[-100:]):
        label=f.get("title") or f.get("name") or f.get("id") or f.get("finding") or f"finding-{i}"
        fid=add_node("finding",label,float(f.get("confidence",f.get("score",.5)) or .5),f if isinstance(f,dict) else {})
        edges.append({"from":nodes[0]["id"],"to":fid,"relation":"exposes","confidence":.7})
        text=_norm(json.dumps(f,ensure_ascii=False) if isinstance(f,dict) else f)
        for typ,words,rel in (("identity",["admin","user","role","jwt","session"],"involves_identity"),("boundary",["idor","authorization","privilege","internal","localhost"],"crosses_boundary"),("sink",["sql","xss","ssti","command","template","file","ssrf"],"reaches_sink")):
            if any(w in text for w in words):
                sid=add_node(typ, next(w for w in words if w in text), .55)
                edges.append({"from":fid,"to":sid,"relation":rel,"confidence":.6})
    story_text=_norm(story)
    if story_text:
        sid=add_node("operator_context",story[:300],.8)
        edges.append({"from":sid,"to":nodes[0]["id"],"relation":"describes","confidence":.8})
    # Candidate transitions are generated from graph signals, not arbitrary commands.
    candidates=[]
    classes=[("access-control","compare identities/objects","high"),("injection","test input-to-sink differential","high"),("authentication","compare session/role boundaries","high"),("routing","inspect proxy/routing trust boundaries","medium"),("file-handling","trace file input to file operation","medium"),("server-side","correlate server-side fetch/template behavior","medium")]
    text=_norm(story)+" "+_norm(json.dumps(findings,ensure_ascii=False))
    for cls,obj,priority in classes:
        hits=sum(text.count(x) for x in cls.split("-"))+sum(text.count(x) for x in {"access-control":"idor authorization role object","injection":"sql sqli xss ssti command","authentication":"jwt session cookie login","routing":"redirect host proxy smuggling","file-handling":"file upload lfi path","server-side":"ssrf template internal"}.get(cls,"").split())
        if hits or cls in {"access-control","authentication"}:
            candidates.append({"id":_id("path",cls+target),"class":cls,"objective":obj,"priority":priority,"information_gain":round(min(1,.35+.12*hits),3),"prerequisites":["in-scope target","relevant evidence"],"status":"candidate"})
    failed={_norm(x.get("candidate_id")) for x in prior if isinstance(x,dict) and x.get("status")=="failed"}
    for c in candidates:
        if c["id"] in failed: c["status"]="failed-before"; c["penalty"]="previously failed; require new evidence"
    candidates.sort(key=lambda x:(x.get("status")=="failed-before",-x["information_gain"],x["id"]))
    return {"schema_version":VERSION,"created_at":time.time(),"target":target,"nodes":nodes,"edges":edges,"next_paths":candidates,"coverage":{"node_count":len(nodes),"edge_count":len(edges),"candidate_count":len(candidates)}}

def write(root: str|Path, **kwargs) -> dict[str,Any]:
    root=Path(root); p=root/"evidence"; p.mkdir(parents=True,exist_ok=True)
    out=build_attack_path(**kwargs); (p/"autonomous-attack-path-v367.json").write_text(json.dumps(out,indent=2,sort_keys=True),encoding="utf-8"); return out

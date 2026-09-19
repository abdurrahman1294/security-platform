#!/usr/bin/env python3
"""Persistent, file-backed engagement knowledge graph; no secrets are stored here."""
from __future__ import annotations
import json, hashlib
from .atomic_io import load_json
from datetime import datetime, timezone
from pathlib import Path

def _load(p,d):
    return load_json(p,d)

def _id(prefix, value): return prefix+hashlib.sha256(value.encode()).hexdigest()[:10]

def build(root: str|Path) -> Path:
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; rep.mkdir(parents=True,exist_ok=True)
    graph=_load(ev/"attack-graph.json",{"nodes":[],"edges":[]}); assets=_load(ev/"assets.json",{"assets":[]}); tech=_load(ev/"technology-inventory.json",{"technologies":[]})
    correlations=_load(ev/"correlation.json",{"correlations":[]}); vals=_load(ev/"validation-ledger.json",[]); ret=_load(ev/"retest-ledger.json",[])
    entities={}; relations=[]
    def add(t,key,props):
        eid=_id(t+"-",t+":"+key); entities[eid]={"id":eid,"type":t,"key":key,"properties":props}; return eid
    for a in assets.get("assets",[]):
        key=str(a.get("host") or a.get("asset_id") or a); add("asset",key,a)
    for n in graph.get("nodes",[]):
        if n.get("type")=="finding":
            fid=str(n.get("finding_id") or n.get("id")); add("finding",fid,{k:n.get(k) for k in ("label","severity","status","confidence","asset","surface")})
    for t in tech.get("technologies",[]): add("technology",str(t.get("name") or t),t)
    for c in correlations.get("correlations",[]):
        if c.get("source") and c.get("target"): relations.append({"type":"correlation","source":c["source"],"target":c["target"],"status":c.get("status","hypothesis")})
    for e in graph.get("edges",[]):
        if e.get("source") and e.get("target"): relations.append({"type":e.get("type","relationship"),"source":e["source"],"target":e["target"],"status":e.get("status","hypothesis"),"confidence":e.get("confidence")})
    kb={"schema_version":"1.0","knowledge_base_id":root.name,"updated":datetime.now(timezone.utc).isoformat(),"policy":{"secrets_excluded":True,"hypotheses_preserved":True},"entities":list(entities.values()),"relations":relations,"validation_count":len(vals),"retest_count":len(ret)}
    p=ev/"knowledge-base.json"; p.write_text(json.dumps(kb,indent=2),encoding="utf-8")
    summary=["# Engagement Knowledge Base","",f"- Entities: **{len(kb['entities'])}**",f"- Relationships: **{len(relations)}**",f"- Validations: **{len(vals)}**",f"- Retests: **{len(ret)}**","","The knowledge base is derived from engagement artifacts. Secrets and raw credentials are intentionally excluded.",""]
    (rep/"knowledge-base.md").write_text("\n".join(summary),encoding="utf-8")
    return p

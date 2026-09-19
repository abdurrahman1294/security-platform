"""V3.6 evidence intelligence fabric.

Turns heterogeneous observations into a conservative asset/evidence graph and
ranks follow-up hypotheses. It never expands scope or executes exploitation.
"""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from modules.atomic_io import atomic_write_json

SURFACES = {
    "ad": "ad-relationships-v32.json",
    "azure": "cloud-azure-assessment-v32.json",
    "gcp": "cloud-gcp-assessment-v32.json",
    "kubernetes": "cloud-kubernetes-assessment-v32.json",
    "container": "container-security-v33.json",
    "database": "database-surface-v33.json",
    "network": "network-device-config-v33.json",
    "services": "service-protocol-intelligence-v35.json",
    "roles": "auth-role-analysis-v35.json",
}

HOST_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,255}$")

def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}

def _rows(doc):
    if isinstance(doc, list): return doc
    if isinstance(doc, dict):
        for k in ("findings", "relationships", "services", "assets", "resources", "items", "tests"):
            if isinstance(doc.get(k), list): return doc[k]
    return []

def _asset(row: dict) -> str:
    for k in ("asset", "host", "address", "hostname", "resource", "principal", "device"):
        v = str(row.get(k) or "").strip()
        if v and HOST_RE.match(v): return v
    return ""

def _nid(kind: str, key: str) -> str:
    return f"{kind}:{hashlib.sha256((kind+'|'+key).encode()).hexdigest()[:14]}"

def build(root: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True, exist_ok=True)
    nodes={}; edges=[]; observations=[]
    def node(kind,key,**meta):
        nid=_nid(kind,key); nodes.setdefault(nid,{"id":nid,"kind":kind,"key":key}); nodes[nid].update({k:v for k,v in meta.items() if v not in (None,"")}); return nid
    def edge(a,b,rel):
        e={"src":a,"dst":b,"rel":rel}
        if e not in edges: edges.append(e)
    for surface, filename in SURFACES.items():
        rows=_rows(_load(ev/filename))
        for i,row in enumerate(rows):
            if not isinstance(row,dict): continue
            asset=_asset(row)
            label=str(row.get("title") or row.get("name") or row.get("id") or row.get("relationship") or f"{surface}-{i}")[:255]
            oid=node("observation", f"{surface}|{label}|{asset}|{i}", surface=surface, label=label, asset=asset, source=filename)
            if asset:
                aid=node("asset",asset,value=asset); edge(aid,oid,"has_observation")
            observations.append({"id":oid,"surface":surface,"label":label,"asset":asset,"source":filename})
    # Only create cross-domain relationships when there is a concrete shared asset.
    by_asset={}
    for o in observations:
        if o["asset"]: by_asset.setdefault(o["asset"],[]).append(o)
    relationships=[]
    for asset, obs in by_asset.items():
        surfaces=sorted({o["surface"] for o in obs})
        if len(surfaces)<2: continue
        aid=node("asset",asset,value=asset)
        for i,a in enumerate(obs):
            for b in obs[i+1:]:
                if a["surface"]==b["surface"]: continue
                edge(aid,a["id"],"anchors"); edge(a["id"],b["id"],"cross-domain-context")
                relationships.append({"asset":asset,"from":a["surface"],"to":b["surface"],"evidence":[a["id"],b["id"]],"confidence":0.75,"status":"hypothesis"})
    data={"schema_version":"3.6","status":"completed","node_count":len(nodes),"edge_count":len(edges),"observation_count":len(observations),"cross_domain_relationships":relationships[:1000],"nodes":list(nodes.values()),"edges":edges,"limitations":["Only shared-asset correlations become cross-domain relationships","A relationship is not proof of reachability or exploitability","All consequential validation remains separately authorized and operator-approved"]}
    atomic_write_json(ev/"intelligence-fabric-v36.json",data)
    return data
